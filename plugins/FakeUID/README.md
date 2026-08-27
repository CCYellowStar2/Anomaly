# Custom UID

`Custom UID 1.1.40` 只修改 NTE 左下角 UID 的本地显示文本，不修改账号数据、网络请求或
服务器状态。

## 使用

- `Display UID`：输入 1 到 256 个单行字符，支持英文、数字、中文和特殊字符。
- `隐藏 UID：前缀`：默认勾选；取消勾选会恢复原生 `UID：` 前缀。
- `Apply`：保存配置，并立即应用到当前已稳定的 RoleID 控件。
- `Revert to original`：恢复自动记录的原始 UID，并关闭覆盖。

输入必须是合法 UTF-8。插件拒绝换行、控制字符、损坏的 UTF-8 和超过 256 个 Unicode
码点的文本。`@#￥%` 等普通符号可直接使用。

勾选时，原生 `UID：` 前缀通过精确控件的 `SetText("")` 隐藏，值控件的 CanvasPanelSlot
自动左移到 X=1；取消勾选时恢复前缀并将值控件恢复到 X=43。两种状态都保留游戏当前的
Y 坐标。UID 值始终按完整字符串处理，英文、数字、中文和特殊字符不会被拆成后缀或重复拼接。
插件窗口允许正常折叠。

插件窗口使用宿主原生字体，不随插件额外打包字体。窗口默认向下加高，并允许在
260×320 到 520×650 范围内拖拽调整。

配置 schema ID 为 `fake-uid-settings-v2`：

```json
{
  "enabled": true,
  "hidePrefix": true,
  "displayUid": "开发测试@#￥%123",
  "detectedUid": "216065736008"
}
```

`detectedUid` 是自动保存的原始数字 UID，不在编辑器中手工填写。

## 生命周期与安全边界

持久化配置会在 RoleID 控件创建并稳定后自动应用；点击 `Apply` 会提高设置 revision，让当前
控件立即更新。BigMap、HUD 重建、传送和重新登录产生新控件时会重新发现并应用。写入前始终
复核 generation、serial、WidgetTree 和 CanvasPanel；不修改 Visibility，只在读取实时位置后按
开关改变 CanvasPanelSlot 的 X 坐标并保留 Y 坐标。

`TextBlock_90` 在原始资产中不是 `bIsVariable`，对象服务不保证能通过模板路径直接返回它。
找不到模板 FName 时，插件会以已确认的 `TextBlock_RoleID` 为锚点，在同一 WidgetTree、同一
`CanvasPanel_0` 的另一个 TextBlock 子控件上恢复前缀。原始资产的该面板只有这两个 TextBlock，
因此不需要放宽到其他 WidgetTree 或其他面板。

值控件始终以完整目标字符串覆盖，不再从当前文本提取并拼接“后缀”，因此中文和特殊字符
在实时更新与周期校验中保持幂等。文本写入复用宿主 ESC 菜单已运行的反射路径：
`KismetTextLibrary.Conv_StringToText -> ProcessEvent(TextBlock.SetText)`。不再手工构造/释放
FText，也不再直接调用 TextBlock 虚表，避免 Slate 后续对已损坏文本数据执行 AddRef。

宿主只提供通用签名扫描、调度、UE 对象快照和名称解析服务。FakeUID 专用签名与布局常量由
插件自己维护；签名不唯一、句柄失效、布局越界或 vtable 不匹配时拒绝写入。

字符串通过 UE 自己的 FString/FText 路径创建和释放，不把插件分配的缓冲交给 UE 持有。

## 构建与部署

```powershell
cmake --preset windows-vs2022
cmake --build .build\windows-vs2022 --config RelWithDebInfo `
  --target anomaly_builtin_fake_uid --parallel 1

.build\windows-vs2022\bin\RelWithDebInfo\anomaly-plugin.exe validate `
  .build\windows-vs2022\bin\RelWithDebInfo\builtin-plugins\FakeUID
```

包输出位于：

```text
.build/windows-vs2022/bin/RelWithDebInfo/builtin-plugins/FakeUID
```

正式部署目录为：

```text
<game>/HT/Binaries/Win64/Anomaly/plugins/FakeUID
```

## 验证要求

- 旧配置没有 `hidePrefix` 时默认按 `true` 加载；
- 勾选时隐藏 `UID：` 并自动左移，取消勾选时恢复前缀和原位置；
- 点击 `Apply` 后当前 RoleID 立即更新；
- 英文、数字、中文和特殊字符都能显示；
- 按 `M` 打开大地图不产生新 UE 崩溃报告；
- `Revert to original` 能恢复自动记录的数字 UID。
