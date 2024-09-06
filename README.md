# SSLCertAutoIssue
免费 乏域名 SSL证书 自动签发部署更新

> Windows下可用的自动重新签发SSL证书脚本，支持泛域名
> 
> 由于在 [Let's Encrypt](https://letsencrypt.osfipin.com/) 申请的证书有效期为90天，所以需要定时更新证书
> 
> 
> 请将配置文件改为自己的信息，第一次启动时会在C:\Users\[UserName]\.SSLCertAutoIssue下创建一个本地的config.yml配置文件，所以需要将这个配置文件的内容修改为用户自己的信息，后续启动从该文件读取配置信息
> 