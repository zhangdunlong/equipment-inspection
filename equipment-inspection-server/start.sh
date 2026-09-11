#!/bin/bash
# 设备点检巡检系统 —— Linux 启动脚本
# 用法：
#   ./start.sh            # 默认端口 8787
#   PORT=9000 ./start.sh  # 自定义端口
# 生产环境推荐用 PM2 守护： pm2 start server.js --name inspection -i 1
cd "$(dirname "$0")"
export PORT="${PORT:-8787}"
exec node server.js
