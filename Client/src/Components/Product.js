// ProductList.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { useStateValue } from '../ContextAPI/StateProvider';
import { actionTypes } from '../ContextAPI/Reducer';

function ProductList() {
    const [products, setProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [{ basket }, dispatch] = useStateValue();

    useEffect(() => {
        const fetchProducts = async () => {
            try {
                const response = await axios.get('https://shopmate-sbxu.onrender.com/products');
                setProducts(response.json());
            } catch (error) {
                setError('Failed to fetch products');
            } finally {
                setLoading(false);
            }
        };

        fetchProducts();
    }, []);
    console.log(products)
    const addToBasket = (product) => {
        dispatch({
            type: actionTypes.ADD_TO_BASKET,
            item: product,
        });
    };

    if (loading) return <div>Loading...</div>;
    if (error) return <div>{error}</div>;

    return (
        <div className="product-list">
            {products.length === 0 ? (
                <div>No products at the moment</div>
            ) : (
                products.map(product => (
                    <div key={product.id} className="product-item">
                        <h2>{product.name}</h2>
                        <p>{product.description}</p>
                        <p>${product.price}</p>
                        <Link to={`/product/${product.id}`} className="btn btn-primary">View Details</Link>
                        <button onClick={() => addToBasket(product)} className="btn btn-add">Add to Cart</button>
                    </div>
                ))
            )}
        </div>
    );
}

export default ProductList;
