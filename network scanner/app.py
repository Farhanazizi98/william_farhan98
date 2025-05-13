from website import create_app, init_db

app = create_app()

init_db()
#with app.app_context():
#    init_db(app)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
    
