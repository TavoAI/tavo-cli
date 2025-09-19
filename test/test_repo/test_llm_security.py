# Test file with potential LLM security issues
import openai
import os

# Potential API key exposure
API_KEY = "sk-1234567890abcdef"  # This should be flagged
api_key = os.getenv("OPENAI_API_KEY")

def chat_with_ai(prompt):
    """Function that might have prompt injection vulnerabilities"""
    system_prompt = "You are a helpful assistant."
    user_input = input("Enter your message: ")  # Direct user input

    # Potential prompt injection - concatenating user input directly
    full_prompt = system_prompt + "\n" + user_input

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}  # Using raw user input
        ],
        api_key=API_KEY  # Using hardcoded API key
    )

    return response.choices[0].message.content

def insecure_model_loading():
    """Function that might load models insecurely"""
    import pickle
    # Loading model from untrusted source
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)  # This is insecure
    return model

if __name__ == "__main__":
    result = chat_with_ai("Hello")
    print(result)