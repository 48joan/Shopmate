    from models import db, User, Product, Wishlist, Favorite, CartItem, Order, Review, SupportRequest, Category
    def seed_data():
    # Sample categories to use for products
    categories = [
        {'name': 'Electronics'},
        {'name': 'Clothing'},
        {'name': 'Books'},
        {'name': 'Home & Kitchen'}
    ]

      with app.app_context():
        for cat in categories:
            category = Category(name=cat['name'])
            db.session.add(category)
        db.session.commit()

        # Fetch categories from database
        categories = Category.query.all()

        products = [
            {
                'name': 'Smartphone',
                'description': 'Latest model smartphone with high-end features.',
                'price': 699.99,
                'rating': 4.5,
                'category_id': categories[0].id,  # Electronics
                'image_url': 'https://www.phoneplacekenya.com/wp-content/uploads/2022/06/Samsung-Galaxy-A54-5G.jpg'
            },
            {
                'name': 'Laptop',
                'description': 'Powerful laptop for work and gaming.',
                'price': 1299.99,
                'rating': 4.7,
                'category_id': categories[0].id,  # Electronics
                'image_url': 'https://www.novelty.co.ke/wp-content/uploads/2024/06/HP-ENVY-x360-14-ES1023-600x600.webp'
            },
            {
                'name': 'Winter Jacket',
                'description': 'Warm and comfortable winter jacket.',
                'price': 199.99,
                'rating': 4.3,
                'category_id': categories[1].id,  # Clothing
                'image_url': 'https://www.zizzifashion.com/dw/image/v2/BGBM_PRD/on/demandware.static/-/Sites-zizzi-Library/default/dwcc686a16/inspiration/Zizzi-Studio/WinterJackets/WinterJacketTileBig.jpg?q=80'
            },
            {
                'name': 'Cooking Essentials',
                'description': 'Complete set of cooking essentials for your kitchen.',
                'price': 89.99,
                'rating': 4.6,
                'category_id': categories[3].id,  # Home & Kitchen
                'image_url': 'https://www.firepit-online.com/media/catalog/product/cache/aa3cf090e9dd4d2788d7fa5e9e7ae9e2/o/n/ontwerp_zonder_titel_-_2023-10-18t163749.976_3.png'
            },
            {
                'name': 'Bestselling Novel',
                'description': 'An engaging novel that you won’t be able to put down.',
                'price': 14.99,
                'rating': 4.8,
                'category_id': categories[2].id,  # Books
                'image_url': 'https://example.com/images/novel.jpg'
            }
        ]

        # Create products
        for prod in products:
            product = Product(
                name=prod['name'],
                description=prod['description'],
                price=prod['price'],
                rating=prod['rating'],
                category_id=prod['category_id'],
                image_url=prod['image_url']
            )
            db.session.add(product)
        db.session.commit()

        print("Seed data has been added.")
        if __name__ == '__main__':
    seed_data()