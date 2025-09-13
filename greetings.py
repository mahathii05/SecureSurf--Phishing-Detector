from ibm_watsonx_orchestrate.agent_builder.tools import tool

@tool(
    name="greeting_tool",
    description="Responds with a friendly custom greeting message."
)
def greeting_tool():
    return "Hey, I’m SecureSurf, your Phishing-check AI assistant !Just send me the URL and i'll quickly check it for you :) 🚀"
