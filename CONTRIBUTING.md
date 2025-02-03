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

2. Install dependencies using Poetry:
   ```sh
   poetry install
   ```

3. Install pre-commit hooks:
   ```sh
   pre-commit install
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
- `pyright` for type checking
- `pre-commit` hooks to automate checks

Please make sure your code passes all checks before submitting a PR:
```sh
pre-commit run --all-files
```

## Pull Request Process

1. Create an issue describing the changes you want to make
2. Fork the repository and create a branch from `main`
3. Make your changes and commit them with clear, descriptive commit messages
4. Update the README.md if needed
5. Add or modify tests as needed
6. Push to your fork and submit a pull request
7. Wait for the review and address any comments

## License

fastapi-jwks is licensed under the [MIT License](https://github.com/bakdata/fastapi-jwks/blob/main/LICENSE).
