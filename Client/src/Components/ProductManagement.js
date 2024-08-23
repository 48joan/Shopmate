import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const ProductManagement = () => {
    const [products, setProducts] = useState([]);
    const [product, setProduct] = useState({
        name: '',
        description: '',
        price: '',
        imageUrl: '',
        categoryId: '',
    });
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const { id } = useParams();
    
    useEffect(() => {
        const fetchProducts = async () => {
            try {
                const response = await fetch('https://shopmate-sbxu.onrender.com/products');
                if (!response.ok) {
                    throw new Error('Failed to fetch products');
                }
                const data = await response.json();
                setProducts(data.products);
            } catch (err) {
                setError(err.message);
            }
        };

        fetchProducts();
    }, []);
    
    useEffect(() => {
        if (id) {
            const fetchProduct = async () => {
                try {
                    const response = await fetch(`https://shopmate-sbxu.onrender.com/products/${id}`);
                    if (!response.ok) {
                        throw new Error('Failed to fetch product');
                    }
                    const data = await response.json();
                    setProduct(data.product);
                } catch (err) {
                    setError(err.message);
                }
            };

            fetchProduct();
        }
    }, [id]);

    const handleChange = (e) => {
        setProduct({ ...product, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const method = id ? 'PUT' : 'POST';
            const url = id ? `https://shopmate-sbxu.onrender.com/products/${id}` : 'https://shopmate-sbxu.onrender.com/products';
            const response = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(product),
            });
            if (!response.ok) {
                throw new Error('Failed to save product');
            }
            navigate('/admin/products');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDelete = async (productId) => {
        try {
            const response = await fetch(`https://shopmate-sbxu.onrender.com/products/${productId}`, {
                method: 'DELETE',
            });
            if (!response.ok) {
                throw new Error('Failed to delete product');
            }
            setProducts(products.filter(p => p.id !== productId));
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="container mx-auto px-4 py-8">
            <h2 className="text-2xl font-bold mb-4 text-black">Manage Products</h2>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <form onSubmit={handleSubmit} className="bg-white p-6 rounded shadow-md border border-black mb-8">
                <h3 className="text-xl font-bold mb-4">Add / Edit Product</h3>
                <div className="mb-4">
                    <label htmlFor="name" className="block text-black font-bold mb-2">Name</label>
                    <input
                        id="name"
                        name="name"
                        type="text"
                        value={product.name}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                        required
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="description" className="block text-black font-bold mb-2">Description</label>
                    <textarea
                        id="description"
                        name="description"
                        value={product.description}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                        required
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="price" className="block text-black font-bold mb-2">Price</label>
                    <input
                        id="price"
                        name="price"
                        type="number"
                        value={product.price}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                        required
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="imageUrl" className="block text-black font-bold mb-2">Image URL</label>
                    <input
                        id="imageUrl"
                        name="imageUrl"
                        type="text"
                        value={product.imageUrl}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="categoryId" className="block text-black font-bold mb-2">Category ID</label>
                    <input
                        id="categoryId"
                        name="categoryId"
                        type="text"
                        value={product.categoryId}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <button
                    type="submit"
                    className={`text-white px-4 py-2 rounded ${id ? 'bg-orange-500 hover:bg-orange-600' : 'bg-green-500 hover:bg-green-600'}`}
                >
                    {id ? 'Update Product' : 'Add Product'}
                </button>
            </form>

            <h2 className="text-2xl font-bold mb-4 text-black">Products List</h2>
            <table className="w-full border-collapse border border-black">
                <thead>
                    <tr>
                        <th className="border border-black px-4 py-2">ID</th>
                        <th className="border border-black px-4 py-2">Name</th>
                        <th className="border border-black px-4 py-2">Price</th>
                        <th className="border border-black px-4 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {products.map(p => (
                        <tr key={p.id}>
                            <td className="border border-black px-4 py-2">{p.id}</td>
                            <td className="border border-black px-4 py-2">{p.name}</td>
                            <td className="border border-black px-4 py-2">${p.price}</td>
                            <td className="border border-black px-4 py-2">
                                <button
                                    onClick={() => navigate(`/admin/products/edit/${p.id}`)}
                                    className="bg-orange-500 text-white px-4 py-2 rounded mr-2 hover:bg-orange-600"
                                >
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleDelete(p.id)}
                                    className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
                                >
                                    Delete
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default ProductManagement;
