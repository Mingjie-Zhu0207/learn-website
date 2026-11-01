# 澄屿作业提交站

一个面向课堂作业的 Flask 网站：学生注册并提交文字/附件，教师发布作业、查看提交并填写成绩与评语。

## 本地运行

1. 安装 Python 3.11 或更新版本。
2. 在此目录运行 `python -m venv .venv`，激活虚拟环境。
3. 运行 `pip install -r requirements.txt`。
4. 设置教师首次登录账号（PowerShell 示例）：

   ```powershell
   $env:SECRET_KEY = "换成一段随机长字符串"
   $env:ADMIN_USERNAME = "teacher"
   $env:ADMIN_PASSWORD = "请换成至少 12 位强密码"
   $env:TEACHER_INVITE_CODE = "仅分享给教师的注册口令"
   python app.py
   ```

5. 打开 `http://127.0.0.1:5000`。学生可从注册页注册；教师可登录预置账号，或在注册时填写教师口令。

首次创建的管理员只会在对应用户名不存在时生成。生产环境请使用唯一、强密码和随机 `SECRET_KEY`，不要把真实密钥提交到 Git。

## 部署到 Render

项目已包含 `render.yaml`。将整个文件夹推送到 GitHub/GitLab 后，在 Render 选择 **New → Blueprint** 并连接仓库。创建时填写 `ADMIN_USERNAME`、`ADMIN_PASSWORD` 和 `TEACHER_INVITE_CODE`。Blueprint 会配置 Python/Gunicorn、健康检查和挂载到 `/var/data` 的持久磁盘。

持久磁盘用于保留 SQLite 数据库和上传附件；Render 文档注明持久磁盘仅适用于付费服务。若选择不带持久磁盘的免费实例，重新部署或实例重启后本地数据库和附件可能丢失。此配置采用一个 Web 实例配一块磁盘，适合小型班级/课程使用。

## 功能与限制

- 学生账号注册、登录和退出；密码使用 Werkzeug 哈希存储。
- 教师新建作业、设置截止时间、查看学生提交、下载附件、录入成绩和评语。
- 学生可编辑文字说明并上传一个附件；再次提交会替换旧附件并清空旧评分。
- 支持 PDF、Office 文档、TXT、ZIP、JPG、PNG，单文件默认上限 20 MB。
- 教师注册口令由 `TEACHER_INVITE_CODE` 环境变量控制；未设置时教师自助注册关闭。
- 当前不含邮箱验证、找回密码、课程分班、在线预览、批量导出或防作弊功能。
