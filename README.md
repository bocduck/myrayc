**This is AI work,use with caution**

# Go VLESS HTTPUpgrade Client

> ...

## Usage
### Run Client
Windows - 直接运行
```
myrayc.exe -c "//example.com:443/?security=tls&path=%2Fsecret_path"
```
Windows - 在 .bat 中运行，百分号要双写转义
```
myrayc.exe -c "//example.com:443/?security=tls&path=%%2Fsecret_path"
```
### Run Chrome
```
start chrome --proxy-server="socks5://127.0.0.1:10809"
```
## Debug
```
curl -x socks5h://127.0.0.1:10809 captive.apple.com
```
