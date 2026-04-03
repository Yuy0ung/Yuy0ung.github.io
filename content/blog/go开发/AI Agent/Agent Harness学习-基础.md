# Agent Harness学习-基础

此笔记诞生的原因是：兴趣使然，我也想写一个渗透Agent，感觉CC的架构是一个很值得参考的东西，于是促使我开始参考 [learn-claude-code](https://github.com/shareAI-lab/learn-claude-code/blob/main/README-zh.md) 学习Agent Harness相关的知识，遂有此篇

在学习之前看到这样一句话：

> **Agent 是模型。不是框架。不是提示词链。不是拖拽式工作流。**

这里奠定了我准备学习的内容：构建 Harness，编写代码，为模型提供一个可操作的环境

## Harness

Harness 是 agent 在特定领域工作所需要的一切：

```
Harness = Tools + Knowledge + Observation + Action Interfaces + Permissions

    Tools:          文件读写、Shell、网络、数据库、浏览器
    Knowledge:      产品文档、领域资料、API 规范、风格指南
    Observation:    git diff、错误日志、浏览器状态、传感器数据
    Action:         CLI 命令、API 调用、UI 交互
    Permissions:    沙箱隔离、审批流程、信任边界                           
```

模型做决策，Harness 执行；模型做推理，Harness 提供上下文

这样看来，其实我们使用的AI IDE也是这样，IDE、终端、文件系统就是为coding Agent提供的harness

## Claude Code

我选择Claude Code的一大原因是它给到模型极高的行为自由度，这和我理想的渗透Agent很相似：
~~~
Claude Code = 一个 agent loop
            + 工具 (bash, read, write, edit, glob, grep, browser...)
            + 按需 skill 加载
            + 上下文压缩
            + 子 agent 派生
            + 带依赖图的任务系统
            + 异步邮箱的团队协调
            + worktree 隔离的并行执行
            + 权限治理
~~~

## Agent Loop

### tool loop

tool loop是AI Agent的最小循环：

~~~
                    THE AGENT PATTERN
                    =================

    User --> messages[] --> LLM --> response
                                      |
                            stop_reason == "tool_use"?
                           /                          \
                         yes                           no
                          |                             |
                    execute tools                    return text
                    append results
                    loop back -----------------> messages[]
~~~

简单描述上面这个loop，就是：

- 没有显式“推理过程”
- LLM只是：
  - 要么说话
  - 要么调用工具

在此技术上我们可以衍生出更合理的loop

### ReAct

即Reasoning + Acting，在基础loop上优化为 **思考-行动-观察** 的循环，即推理下一步应该干什么，再执行对应的行为，最后观察行动的结果，进行下一个loop的推理

### Plan-and-Execute

将复杂任务分解为规划和执行两个阶段，由planner制定计划，executor机械执行，实现上通常需要维护一个任务队列和状态管理器，记录每个任务的依赖关系和完成状态，相较于ReAct：

* ReAct倾向于走一步看一步，适用于变数较多的场景
* Plan-and-Execute适用于步骤相对确定的复杂任务，既能节省Token成本，执行也能更可控

