### Welcome to QLE encryption. QLE allows you to safely and secur(ish)ly transfer files between two go scripts. QLE utilizes ecDSA, ecDH, AES_CTR, and HMAC to set up a channel to communicate safely between processes.

## To run:
1. Place whatever file you want to copy into the server folder. Change the name of fileToCopy on line 14 in server.go, and the name of downloadedFile on line 16 on client.go 

2. On one terminal, run the server with
```bash
go run server.go cryptoTools.go send-recv.go
```

3. On another terminal, run the client with
```bash
go run client.go cryptoTools.go send-recv.go
```

