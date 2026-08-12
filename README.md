# ClashHelper

自动拉取、过滤、测速、合并订阅节点至自己的 Clash 配置模板。

## 工作流程

1. 并发拉取 `sources.yaml` 里的全部订阅源
2. 按 `exclusion` / `inclusion` 关键词过滤节点名称和地址
3. 把所有源的节点汇总成一批，一次性并发测延迟
4. 只保留延迟低于 **500ms** 的节点，按延迟升序排列
5. 节点名加上订阅源前缀（`FREESUB-香港01`），追加进模板并写出配置

输出的配置文件不包含模板中的注释，不影响使用。节点条目里会带 `_orig_name`、`latency`、`subscription` 三个额外字段，Clash 会忽略它们。

## 延迟检测

测速端点是 `http://www.google.com/generate_204`，明文 HTTP、GET 请求，正常返回 HTTP 204。

## 更新

Github 随缘更新（Action 机器测试不准确，有需要的 clone 到本地自己运行）。

## 用法

```text
python3 helper.py <sources_config> [output]

python3 helper.py sources.yaml
python3 helper.py sources.yaml output.yaml
```

## 配置订阅源

`sources.yaml`，注意顶层必须是 `sources:` 键：

```yaml
sources:
  - name: mySite            # 订阅源名称，用于日志和节点名前缀，必须唯一
    url: https://example.com/v1/abcd   # Clash 配置文件的订阅 URL
    group: PROXY            # 目标代理组名，可省略，默认 PROXY
    exclusion:              # 名称或地址包含这些关键词的节点会被丢弃
      - 127.0.0.1
      - 官网
      - 测试
    inclusion:              # 仅采纳包含这些关键词的节点，可省略
      - 香港
      - 新加坡
      - 日本
```

只有 `url` 是必填。`name` 省略时从 URL 域名推断，但强烈建议写明 —— 程序靠它把测速结果分回各个源，重名会直接报错退出。

`exclusion` 先执行，`inclusion` 后执行。两者都不写就是不做关键词过滤。

## 模板文件

`template.yaml` 是一个预置的 Clash 配置文件，`dns`、`rules` 等内容会原样保留。

需要注意的是：程序会把模板里的 `proxies` 和 `proxy-groups` **整体替换掉**，替换成一个名为 `PROXY` 的 `select` 组。也就是说在模板里自己定义代理分组是**不生效的**，`sources.yaml` 里的 `group` 字段目前只能填 `PROXY`（或省略）。填了别的名字，那个源的节点会进 `proxies` 但不属于任何分组，在 Clash 里选不到 —— 程序会为此打出警告。
