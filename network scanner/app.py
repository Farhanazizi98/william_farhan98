from website import create_app, init_db

app = create_app()

#initialize the database
init_db()

#run the app
if __name__ == '__main__':
    app.run(debug=True, port=5000)
    
