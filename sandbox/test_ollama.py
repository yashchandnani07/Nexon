import httpx, asyncio, os

async def test():
    host = os.environ.get("OLLAMA_HOST", "http://sandbox_ollama:11434")
    print(f"Calling tinyllama at {host}...")
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f"{host}/api/chat", json={
            "model": "tinyllama",
            "messages": [{"role": "user", "content": "Say hello in 5 words"}],
            "stream": False,
            "options": {"num_predict": 20}
        })
        print(f"STATUS: {r.status_code}")
        data = r.json()
        print(f"RESPONSE: {data['message']['content'][:200]}")

asyncio.run(test())
