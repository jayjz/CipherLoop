from langchain_ollama import ChatOllama
llm = ChatOllama(model='qwen-coder-7b', base_url='http://localhost:11434')
response = llm.invoke("Say 'Local model loaded successfully'")
print(response.content)
