import os


def load_prompt(agent: str, node_name: str):
    # Get the absolute path of the prompt file
    prompt_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "Prompts",
        agent,
        f"{node_name}.md",
    )

    if not os.path.exists(prompt_path):
        raise FileNotFoundError(
            f"Prompt file {node_name}.md not found for agent {agent}."
        )

    with open(prompt_path, "r") as file:
        prompt = file.read()

    return prompt