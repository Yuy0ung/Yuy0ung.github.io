# Agent Harness学习-Loop

接下来实践前面提到的loop

我们通过一个简单的while循环实现最简单的harness，流程图如下：

![image-20260331133804575](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/image-20260331133804575.png)

在这里，我们将Execute Tool选定为bash：

> Bash 能读写文件、运行任意程序、在进程间传递数据、管理文件系统。任何额外的工具（read_file、write_file 等）都只是  bash 已有能力的子集。增加工具并不会解锁新能力，只会增加模型需要理解的接口。模型只需学习一个工具的 schema，实现代码不超过 100  行。这就是最小可行 agent：一个工具，一个循环

## 开发

我们先给出伪代码：

~~~go
for {
    resp := callLLM(messages, tools)
    appendAssistant(resp)
    if resp.StopReason != tool_use {
        break
    }
    results := execTools(resp.ToolUses)
    appendUser(results)
}
~~~

接下来站在开发者视角一步一步完成这个最小实践：

太好了，这个需求很清晰。下面我按你给的风格，写一版**站在开发者视角、一步一步搭建最小 Go Agent** 的教学文档，重点放在 `loop`、`runBash`、`main`，同时把当前代码里的函数一个不漏讲到。

### 环境与客户端初始化

- 先解决配置输入：加载 `.env` 并覆盖同名环境变量（对齐 Python `load_dotenv(override=True)`）。
- 再解决客户端初始化：如果设置了 `ANTHROPIC_BASE_URL`，就走自定义 base URL，并移除 `ANTHROPIC_AUTH_TOKEN`。

这里比较简单，不放代码了

### 工具调用能力（runBash）

- 需求：模型产出 `bash` 命令后，在本地执行并返回输出。
- 核心点有三个：危险命令拦截、120 秒超时、输出长度限制。
- 这部分与 loop 解耦，后续换 SSH 或容器执行器都不影响 loop 主体。

代码：

```go
func runBash(command string) string {
	dangerous := []string{"rm -rf /", "sudo", "shutdown", "reboot", "> /dev/"}
	for _, d := range dangerous {
		if strings.Contains(command, d) {
			return "Error: Dangerous command blocked"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	cmd.Dir, _ = os.Getwd()
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "Error: Timeout (120s)"
	}

	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		output = err.Error()
	}
	if output == "" {
		output = "(no output)"
	}
	if len(output) > maxOutputChars {
		return output[:maxOutputChars]
	}
	return output
}
```

---

### Loop 实现

1) 用户消息先进入 `history`（在 main 里完成）：

```go
history = append(history, anthropic.NewUserMessage(anthropic.NewTextBlock(query)))
```

2) 在 loop 内把消息 + 工具 + system + model 发给 LLM：

```go
resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
    Model:     MODEL,
    MaxTokens: 8000,
    System:    []anthropic.TextBlockParam{{Text: SYSTEM}},
    Messages:  *messages,
    Tools:     TOOLS,
})
```

3) 追加 assistant 响应；若不是 `tool_use` 就结束：

```go
*messages = append(*messages, anthropic.NewAssistantMessage(toParams(resp.Content)...))
if resp.StopReason != anthropic.StopReasonToolUse {
    return nil
}
```

4) 执行每个 `tool_use`，组装 `tool_result`，再作为一条 `user` 消息追加：

```go
results := make([]anthropic.ContentBlockParamUnion, 0)
for _, block := range resp.Content {
    toolUse, ok := block.AsAny().(anthropic.ToolUseBlock)
    if !ok {
        continue
    }
    var input struct {
        Command string `json:"command"`
    }
    _ = json.Unmarshal(toolUse.Input, &input)

    output := runBash(input.Command)
    results = append(results, anthropic.NewToolResultBlock(toolUse.ID, output, false))
}
*messages = append(*messages, anthropic.NewUserMessage(results...))
```

完整函数：

```go
func agentLoop(ctx context.Context, messages *[]anthropic.MessageParam) error {
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
		for _, block := range resp.Content {
			toolUse, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			var input struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal(toolUse.Input, &input)

			fmt.Printf("\033[33m$ %s\033[0m\n", input.Command)
			output := runBash(input.Command)
			fmt.Println(truncateString(output, 200))

			results = append(results, anthropic.NewToolResultBlock(toolUse.ID, output, false))
		}
		*messages = append(*messages, anthropic.NewUserMessage(results...))
	}
}
```

---

### 入口函数main

- `main` 负责把所有能力串起来：加载配置、校验模型、构造系统提示词、初始化 client、进入 REPL
- 每轮 REPL：
  - 读取用户输入
  - 处理退出条件 `q/exit/空`
  - append user message
  - 调 `agentLoop`
  - 打印最后一次 assistant 的 text 内容

代码：

```go
func main() {
	envloader.LoadDotEnvOverride(".env")

	modelID := os.Getenv("MODEL_ID")
	if modelID == "" {
		fmt.Fprintln(os.Stderr, "MODEL_ID is required")
		os.Exit(1)
	}

	wd, _ := os.Getwd()
	SYSTEM = fmt.Sprintf("You are a coding agent at %s. Use bash to solve tasks. Act, don't explain.", wd)
	MODEL = anthropic.Model(modelID)

	if os.Getenv("ANTHROPIC_BASE_URL") != "" {
		_ = os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
		client = anthropic.NewClient(option.WithBaseURL(os.Getenv("ANTHROPIC_BASE_URL")))
	} else {
		client = anthropic.NewClient()
	}
	ctx := context.Background()
	history := make([]anthropic.MessageParam, 0)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\033[36ms01 >> \033[0m")
		query, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		query = strings.TrimRight(query, "\r\n")
		normalized := strings.ToLower(strings.TrimSpace(query))
		if normalized == "q" || normalized == "exit" || normalized == "" {
			break
		}

		history = append(history, anthropic.NewUserMessage(anthropic.NewTextBlock(query)))
		if err := agentLoop(ctx, &history); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
			continue
		}
		if len(history) > 0 {
			printAssistantText(history[len(history)-1].Content)
		}
		fmt.Println()
	}
}
```

### 一些细节

这里针对golang做了一点特殊实现

- `toParams`：把 SDK 响应块转换成下一轮可回放的参数块（Go 强类型下必须有这层）  
- `truncateString`：用于 CLI 打印时截断（例如工具输出预览 200 字符）
- `printAssistantText`：只输出 assistant 的 text block，避免把非文本 block 直接打印 
- `LoadDotEnvOverride`：`.env` 加载器（单独模块便于复用）

## 运行

完成上述任务后，我们为大模型提供了一个最简单的harness，运行试试：
![2026-03-31_16-03-42](https://yuy0ung.oss-cn-chengdu.aliyuncs.com/2026-03-31_16-03-42.png)

可以看到我们大模型能很完美的完成我们的要求，至此我们正式完成了一个基于loop，最简单的harness