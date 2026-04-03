# Agent Harness学习-Subagent

在前面的实验中，可能会想到这个问题：

agent工作越久，其messages存储的信息就越多，因为工具调用的结果都会在其中，所以我们需要使用subagent来优化，即构建出上下文隔离，Subagent 用独立 messages[]， 不污染主对话，架构如下：

~~~
Parent agent                     Subagent
+------------------+             +------------------+
| messages=[...]   |             | messages=[]      | <-- fresh
|                  |  dispatch   |                  |
| tool: task       | ----------> | while tool_use:  |
|   prompt="..."   |             |   call tools     |
|                  |  summary    |   append results |
|   result = "..." | <---------- | return last text |
+------------------+             +------------------+

Parent context stays clean. Subagent context is discarded.
~~~

## 开发

### 父agent

父 Agent 有一个 task 工具。Subagent 拥有除 task 外的所有基础工具（禁止递归生成）
代码中，我们通过切片构造来实现这一逻辑。`CHILD_TOOLS` 包含 `bash`, `read_file`, `write_file`, `edit_file`。`PARENT_TOOLS` 则在此基础上，追加一个名为 `task` 的委派工具

代码如下：
```go
var CHILD_TOOLS = []anthropic.ToolUnionParam{
	// ... bash, read_file, write_file, edit_file ...
}

var PARENT_TOOLS []anthropic.ToolUnionParam

func init() {
	PARENT_TOOLS = make([]anthropic.ToolUnionParam, len(CHILD_TOOLS))
	copy(PARENT_TOOLS, CHILD_TOOLS)
	PARENT_TOOLS = append(PARENT_TOOLS, anthropic.ToolUnionParam{
		OfTool: &anthropic.ToolParam{
			Name:        "task",
			Description: anthropic.String("Spawn a subagent with fresh context. It shares the filesystem but not conversation history."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{
					"prompt":      map[string]any{"type": "string"},
					"description": map[string]any{"type": "string", "description": "Short description of the task"},
				},
				Required: []string{"prompt"},
			},
		},
	})
}
```

### Subagent

Subagent 以全新的 `messages=[]` 启动，运行自己的循环。只有最终文本返回给父 Agent
当父 Agent 的循环（`agentLoop`）拦截到工具名为 `task` 时，将不再去 `TOOL_HANDLERS` 找具体实现，而是把 `prompt` 交给 `runSubagent` 函数，在一个崭新的隔离环境里运行

代码：
```go
func runSubagent(ctx context.Context, prompt string) string {
	subMessages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)), // 全新的 messages=[] 启动
	}

	for i := 0; i < 30; i++ { // safety limit
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     MODEL,
			System:    []anthropic.TextBlockParam{{Text: SUBAGENT_SYSTEM}},
			Messages:  subMessages,
			Tools:     CHILD_TOOLS, // Subagent 仅拥有基础工具
		})

		subMessages = append(subMessages, anthropic.NewAssistantMessage(toParams(resp.Content)...))

		if resp.StopReason != anthropic.StopReasonToolUse {
			// 没有工具调用，循环终止，提取所有的 Text block 拼成摘要并返回
			var summary strings.Builder
			for _, block := range resp.Content {
				b, ok := block.AsAny().(anthropic.TextBlock)
				if ok {
					summary.WriteString(b.Text)
				}
			}
			if res := summary.String(); res != "" {
				return res
			}
			return "(no summary)"
		}

		// ...执行工具调用，把 tool_result 追加到 subMessages 里继续下一轮...
	}
	// ...
}
```

### 关于隔离

“进程隔离即上下文隔离”：Subagent 可能跑了 30 多次工具调用（例如不停地通过 grep、read_file 试错找代码），但在它的生命周期结束时，这个长长的 `subMessages` 历史会被直接丢弃，并没有被加入到父级的 `history` 里。父 Agent 收到并看到的，仅仅是一段 `runSubagent` 返回的文本摘要，作为普通的 `tool_result` 结果。这既能完成繁琐的探索任务，又不会让一长串日志污染父 Agent 视角的清晰度

## 运行

接下来运行测试，同样没有问题：

![image-20260402153342025](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20260402153342025.png)