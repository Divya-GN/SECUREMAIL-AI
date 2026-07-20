import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Retrieve port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    print(f"Launching SecureMail AI threat scanning portal...")
    print(f"Server available at http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=True)
