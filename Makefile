build:; go build -o target/smtp *.go

build-linux:; export GOOS=linux && export GOARCH=amd64 && go build -o target/smtp *.go

clean:; rm -rf target/*

test:; go test -v



