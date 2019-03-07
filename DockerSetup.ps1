docker pull microsoft/mssql-server-linux
docker images
docker run -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=Pass@Word1" `
        -p 11433:1433 --name mssqlLinux `
        -v C:\docker\linux\sql:/sql `
        -v C:\docker\linux\data:/data `
        -v C:\docker\linux\log:/log `
        -v C:\docker\linux\backups:/backups `
        -d 314918ddaedf
docker container ls -a

docker stop 40bcd8c2a706
docker rm 40bcd8c2a706 
docker stats 4898fb426ffe
docker run --help