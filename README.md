# smart-edge-challenge

Submission for https://smart-edge.com/codechallenge/

To run static checks and unit tests:
```
go test -v ./...
```

To run the program, run the following commands from the project root:
```bash
docker build . -t <image name>
docker run <image name> <input message>
```
