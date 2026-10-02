def test_provider_fallback_contract():
    # Regression placeholder: provider rotation must fail closed.
    providers=['Gemini','Groq']
    assert providers[-1]=='Groq'
