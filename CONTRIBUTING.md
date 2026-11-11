# Contributing

Thank you for considering contributing to fastapi-jwks! We appreciate your help in making this project better.

## How to contribute

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Make your changes
4. Write or adapt tests as needed
5. Update the documentation if necessary
6. Submit a pull request

## Development setup

1. Clone your fork:
   ```sh
   git clone https://github.com/YOUR_USERNAME/fastapi-jwks.git
   cd fastapi-jwks
   ```

2. Install [mise](https://mise.jdx.dev/) and set up the tools and Git hooks (installs [hk](https://hk.jdx.dev) and syncs dependencies with [uv](https://docs.astral.sh/uv/)):
   ```sh
   mise install
   ```

## Running tests

To run tests:
```sh
pytest
```

To run tests with coverage:
```sh
pytest --cov=fastapi_jwks
```

## Code style

We use the following tools to maintain code quality:
- `ruff` for both linting and formatting
- `ty` for type checking
- [`hk`](https://hk.jdx.dev) Git hooks to automate checks

Please make sure your code passes all checks before submitting a PR:
```sh
hk check --all
```

## Pull Request Process

We are happy if you want to contribute to this project. If you find any bugs or have suggestions for improvements, please open an issue. We are also happy to accept your PRs. Just open an issue beforehand and let us know what you want to do and why.

## License

fastapi-jwks is licensed under the [MIT License](https://github.com/bakdata/fastapi-jwks/blob/main/LICENSE).
