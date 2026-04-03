---
title: "Agent Harness学习-规划"
date: 2026-04-03T00:00:00+08:00
draft: false
weight: 4
---

# Agent Harness学习-规划

在前面的agent开发中，不难发现，我们的loop已经具有了简单的ReAct能力，能思考，调用tools，根据tools调用的结果来“隐式”推理，再思考下一步...

多步任务中, 模型会丢失进度 -- 重复做过的事、跳步、跑偏。对话越长越严重: 工具结果不断填满上下文, 系统提示的影响力逐渐被稀释。一个 10 步重构可能做完 1-3 步就开始即兴发挥, 因为 4-10 步已经被挤出注意力了，此时就需要我们参考先前提到过的Plan-and-Execute

## 设计

那么接下来我们继续优化，我们不需要像标准的Plan-and-Execute，只需要再我们的tools工具中加一个todo用于大模型规划即可，设计如下架构：

~~~
+--------+      +-------+      +---------+
|  User  | ---> |  LLM  | ---> | Tools   |
| prompt |      |       |      | + todo  |
+--------+      +---+---+      +----+----+
                    ^                |
                    |   tool_result  |
                    +----------------+
                          |
              +-----------+-----------+
              | TodoManager state     |
              | [ ] task A            |
              | [>] task B  <- doing  |
              | [x] task C            |
              +-----------------------+
                          |
              if rounds_since_todo >= 3:
                inject <reminder> into tool_result
~~~

我们不让模型在思维链中默默规划，而是强制通过 TodoWrite  工具将计划外化。每个计划项都有可追踪的状态（pending、in_progress、completed）。这有三个好处：

* 用户可以在执行前看到 agent 打算做什么
* 开发者可以通过检查计划状态来调试 agent 行为
* agent  自身可以在后续轮次中引用计划，即使早期上下文已经滚出窗口

另外，TodoWrite 工具应该要求任何时候最多只能有一个任务处于 in_progress  状态，如果模型想开始第二个任务，必须先完成或放弃当前任务。这个约束防止了一种隐蔽的失败模式：试图通过交替处理多个项目来'多任务'的模型，往往会丢失状态并产出半成品。顺序执行的专注度远高于并行切换

最后，TodoWrite 将计划项限制在 20 条以内。这是对过度规划的刻意约束。不加限制时，模型倾向于将任务分解成越来越细粒度的步骤，产出 50  条的计划，每一步都微不足道。冗长的计划很脆弱：如果第 15 步失败，剩下的 35 步可能全部作废。20  条以内的短计划保持在正确的抽象层级，更容易在现实偏离计划时做出调整

## 开发

### TodoManager

给模型一个必须显式维护的计划状态：

- `TodoManager` 存储带状态的任务项，状态只有 `pending / in_progress / completed`
- `Update` 会校验输入，统计 `in_progress` 数量；如果超过 1 个，直接报错
- 更新成功后把结构化任务写回内存，并返回渲染后的可读文本

代码：

```go
type TodoItem struct {
	ID     string
	Text   string
	Status string
}

type TodoManager struct {
	Items []TodoItem
}

func (t *TodoManager) Update(items []map[string]any) (string, error) {
	if len(items) > 20 {
		return "", fmt.Errorf("Max 20 todos allowed")
	}
	validated := make([]TodoItem, 0, len(items))
	inProgressCount := 0
	for i, item := range items {
		text := strings.TrimSpace(fmt.Sprint(item["text"]))
		status := strings.ToLower(strings.TrimSpace(getDefaultString(item, "status", "pending")))
		itemID := strings.TrimSpace(getDefaultString(item, "id", strconv.Itoa(i+1)))
		if text == "" {
			return "", fmt.Errorf("Item %s: text required", itemID)
		}
		if status != "pending" && status != "in_progress" && status != "completed" {
			return "", fmt.Errorf("Item %s: invalid status '%s'", itemID, status)
		}
		if status == "in_progress" {
			inProgressCount++
		}
		validated = append(validated, TodoItem{
			ID:     itemID,
			Text:   text,
			Status: status,
		})
	}
	if inProgressCount > 1 {
		return "", fmt.Errorf("Only one task can be in_progress at a time")
	}
	t.Items = validated
	return t.Render(), nil
}
```

### dispatch map

- `todo` 工具和其他工具一样，只是在dispatch map中多了一个 handler
- 模型调用 `todo` 时，本质上还是“工具名 → handler”的普通分发，没有特殊框架

代码：

```go
var TOOL_HANDLERS = map[string]toolHandler{
	"bash": func(kw map[string]any) (string, error) {
		// ......
	},
	"read_file": func(kw map[string]any) (string, error) {
		// ......
	},
	"write_file": func(kw map[string]any) (string, error) {
		// ......
	},
	"edit_file": func(kw map[string]any) (string, error) {
		// ......
	},
	"todo": func(kw map[string]any) (string, error) {
		items, err := getItems(kw, "items")
		if err != nil {
			return "", err
		}
		return TODO.Update(items)
	},
}
```

### schema

- `todo` 也要像别的工具一样定义 schema
- 这里最重要的是 `items` 是数组，数组元素是对象，对象必须有 `id / text / status`
- `status` 还用 `enum` 限死为三种状态，避免模型乱传

代码：

```go
{
	OfTool: &anthropic.ToolParam{
		Name:        "todo",
		Description: anthropic.String("Update task list. Track progress on multi-step tasks."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"items": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"id": map[string]any{
								"type": "string",
							},
							"text": map[string]any{
								"type": "string",
							},
							"status": map[string]any{
								"type": "string",
								"enum": []string{"pending", "in_progress", "completed"},
							},
						},
						"required": []string{"id", "text", "status"},
					},
				},
			},
			Required: []string{"items"},
		},
	},
}
```

### nag reminder

我们需要在loop中加一个reminder机制：

- nag reminder 的逻辑是：如果模型连续 3 轮没调用 `todo`，就给下一轮上下文塞一个提醒
- 这里的方法是**在当前轮的 `tool_result` user 消息里追加一个 text block reminder**

代码：

```go
func agentLoop(ctx context.Context, messages *[]anthropic.MessageParam) error {
	roundsSinceTodo := 0
	for {
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     MODEL,
			MaxTokens: 8000,
			System:    []anthropic.TextBlockParam{{Text: SYSTEM}},
			Messages:  *messages,
			Tools:     TOOLS,
		})
		if err != nil {
			return err
		}

		*messages = append(*messages, anthropic.NewAssistantMessage(toParams(resp.Content)...))

		if resp.StopReason != anthropic.StopReasonToolUse {
			return nil
		}

		results := make([]anthropic.ContentBlockParamUnion, 0)
		usedTodo := false
		for _, block := range resp.Content {
			toolUse, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			var input map[string]any
			_ = json.Unmarshal(toolUse.Input, &input)
			handler := TOOL_HANDLERS[toolUse.Name]
			output := ""
			if handler == nil {
				output = fmt.Sprintf("Unknown tool: %s", toolUse.Name)
			} else {
				output, err = handler(input)
				if err != nil {
					output = "Error: " + err.Error()
				}
			}
			results = append(results, anthropic.NewToolResultBlock(toolUse.ID, output, false))
			if toolUse.Name == "todo" {
				usedTodo = true
			}
		}
		if usedTodo {
			roundsSinceTodo = 0
		} else {
			roundsSinceTodo++
		}
		if roundsSinceTodo >= 3 {
			results = append(results, anthropic.NewTextBlock("<reminder>Update your todos.</reminder>"))
		}
		*messages = append(*messages, anthropic.NewUserMessage(results...))
	}
}
```

### 总结

`"同时只能有一个 in_progress"` 的意义是强制模型把注意力放在一个当前任务上，而不是同时推进多个任务

nag reminder 的意义是制造持续问责：你如果一直不更新计划，系统就会把“该更新 todo”重新塞回上下文

## 运行

完成上述任务后，我们尝试运行一个多步骤的任务：

![image-20260401171528903](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20260401171528903.png)

可以看到大模型使用todo规划了三步，最后成功完成了这个任务