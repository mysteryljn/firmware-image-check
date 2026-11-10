# firmware-image-check

离线检查 Intel HEX 与 Motorola S-record 固件镜像：校验记录长度/校验和/结束记录，检查地址窗口、稀疏重叠和入口点，并按擦除块比较两个镜像。空洞不会被擅自当作 `0xFF`。支持 JSON、Markdown、自包含 HTML 报告；门禁失败返回退出码 1，输入错误返回 2。

```powershell
python -m pip install "firmware-image-check @ git+https://github.com/mysteryljn/firmware-image-check.git"
python -m firmware_image_check demo --output report.html
python -m firmware_image_check check build/app.hex --allow 0x08000000:0x08100000 --require-entrypoint
```

仓库 fixture 是合成样例，只用于展示报告流程。工具不推断芯片擦除值、ARM Thumb 入口掩码或设备行为；为避免歧义会拒绝所有重叠记录。项目为工程辅助工具，不能替代量产烧录器或认证流程。
