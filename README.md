# How to use uv system, we use it because its much faster and easier to maintain than requirements.txt
pip install uv
uv sync
.venv\Scripts\activate (for windows)

# If your adding new libraries to our project!

add it to pyproject.toml in a similar format try to use >= version
uv lock
uv sync
.venv