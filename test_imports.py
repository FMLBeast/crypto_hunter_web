# Simple script to test if the circular import issue is resolved
try:
    print("Importing User from crypto_hunter_web.models...")
    from crypto_hunter_web.models import User
    print("✅ Successfully imported User")
    
    print("Importing models from crypto_hunter_web.models.puzzle...")
    from crypto_hunter_web.models.puzzle import PuzzleSession
    print("✅ Successfully imported PuzzleSession")
    
    print("All imports successful! The circular import issue is resolved.")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("The circular import issue might still exist.")
except Exception as e:
    print(f"❌ Other error: {e}")