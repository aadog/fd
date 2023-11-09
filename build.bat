wsl go build -x -v -o ./fd -ldflags="-s -w"
upx ./fd
