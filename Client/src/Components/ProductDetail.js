// ProductDetails.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';
import { useStateValue } from '../ContextAPI/StateProvider';
import { actionTypes } from '../ContextAPI/Reducer';

function ProductDetails() {
    const [product, setProduct] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const { id } = useParams();
    const [{ basket }, dispatch] = useStateValue();

    useEffect(() => {
        const fetchProduct = async () => {
            try {
                const response = await axios.get(`/products/${id}`);
                setProduct(response.data);
            } catch (error) {
                setError('Failed to fetch product details');
            } finally {
                setLoading(false);
            }
        };

        fetchProduct();
    }, [id]);

    const addToBasket = () => {
        dispatch({
            type: actionTypes.ADD_TO_BASKET,
            item: product,
        });
    };

    const removeFromBasket = () => {
        dispatch({
            type: actionTypes.REMOVE_FROM_BASKET,
            id: product.id,
        });
    };

    if (loading) return <div>Loading...</div>;
    if (error) return <div>{error}</div>;

    if (!product) return <div>No product found</div>;

    const isInBasket = basket.some(item => item.id === product.id);

    return (
        <div className="product-details">
            <h1>{product.name}</h1>
            <p>{product.description}</p>
            <p>${product.price}</p>
            <button onClick={isInBasket ? removeFromBasket : addToBasket} className="btn btn-add-remove">
                {isInBasket ? 'Remove from Cart' : 'Add to Cart'}
            </button>
        </div>
    );
}

export default ProductDetails;
