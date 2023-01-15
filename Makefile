start-server:
	cargo watch -q -c -w src/ -x run

install:
	cargo add actix-web
	cargo add actix-cors
	cargo add totp-rs
	cargo add base32
	cargo add rand
	cargo add serde --features derive
	cargo add serde_json
	cargo add chrono --features serde
	cargo add env_logger
	cargo add uuid --features v4
	# HotReload
	cargo install cargo-watch 