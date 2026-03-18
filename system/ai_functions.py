from google import genai
from openai import OpenAI

def ai_chat_request(chat_type="chatgpt", text="Hello!", api_key="1234", options={}):
    chat_type = chat_type.lower().strip()
    if chat_type == "chatgpt":
        return chatgpt_request(text, api_key, options=options)
    elif chat_type == "gemini":
        return gemini_request(text, api_key, options=options)
    elif chat_type == "deepseek":
        return deepseek_request(text, api_key, options=options)
    else:
        raise Exception("Unknown AI chat name")


def chatgpt_request(text, api_key, options={}):
    client = OpenAI(api_key=api_key)

    instructions = ""
    if "instructions" in options:
        instructions = str(options[instructions])

    response = client.responses.create(
        model="gpt-4o",
        instructions=instructions,
        input=text,
    )

    return str(response.output_text).strip(" \r\n\t")


def gemini_request(text, api_key, options={"model_name": "gemini-2.5-pro"}):

    model_name = "gemini-2.5-pro"
    if "model" in options:
        model_name = options["model"]

    client = genai.Client(api_key=api_key)
    chat = client.chats.create(model=model_name)

    response = chat.send_message(text)
    return str(response.text).strip(" \r\n\t")


def deepseek_request(text, api_key, options={}):
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    content = ""

    if "content" in options:
        content = str(options["content"])

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": content},
            {"role": "user", "content": text},
        ],
        stream=False
    )

    return str(response.choices[0].message.content).strip(" \r\n\t")
