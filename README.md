# Домашнее задание к лекции «Flask»

## Для запуска необходимо выполнить следующие действия:
 
1. Необходимо переименовать файл переменных окружения
`mv _env .env`
2. Установить зависимости
`pip install -r requirements.txt`
3. Запустить контейнер
`docker-compose up -d`
4. Сервис доступен по адресу http://localhost:5000/

## В разработанном приложение доступно следующие API

1. `/` метод GET - главная страница, показывает все обьявления в базе данных для всех пользователей
2. `/user/{user_id}/products` метод GET - показывает все обьявления определенного пользователя для всех пользователей
3. `/user/` метод POST - создает пользователя.
Необходимо передать в теле запроса данные в формате JSON

```json
{
    "name": "user_name",
    "password": "user_password",  
    "email": "user_email"
}
```
4. `/user/{user_id}/` метод PATCH - обновляет данные пользователя, требуется авторизация.
Необходимо передать в теле запроса данные в формате JSON и заголовок Authorization
```json
{
    "name": "user_name",
    "password": "user_password",  
    "email": "user_email"
}
```
    auth=(USER_NAME, USER_PASSWORD)
5. `/user/{user_id}/` метод DELETE - удаляет данные пользователя, требуется авторизация.
Необходимо передать в теле запроса заголовок Authorization
```
    auth=(USER_NAME, USER_PASSWORD)
```
6. `/user/{user_id}/` метод GET - показывает информацию о пользователе.
7. `/product/` метод POST - создает объявление, требуется авторизация.
Необходимо передать в теле запроса данные в формате JSON и заголовок Authorization
```json
{
    "name": "Заголовок",
    "description": "Описание",
    "price": "Цена",
    "count": "Колличество"
}
```
    auth=(USER_NAME, USER_PASSWORD)


8. `/product/{product_id}/` метод PATCH - обновляет обьявление, требуется авторизация. Доступн только для владельца обьявления.
Необходимо передать в теле запроса данные в формате JSON и заголовок Authorization
```json
{
    "name": "Заголовок",
    "description": "Описание",
    "price": "Цена",
    "count": "Колличество"
}
```
    auth=(USER_NAME, USER_PASSWORD)

9. `/product/{product_id}/` метод DELETE - удаляет обьявление, требуется авторизация. Доступн только для владельца обьявления.
Необходимо передать в теле запроса заголовок Authorization
```
    auth=(USER_NAME, USER_PASSWORD)
```
10. `/product/{product_id}/` метод GET - показывает информацию об обьявлении.
11. `/users/` метод GET - показывает всех пользователей.