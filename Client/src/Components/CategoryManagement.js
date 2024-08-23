import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const CategoryManagement = () => {
    const [categories, setCategories] = useState([]);
    const [category, setCategory] = useState({ name: '' });
    const [isEditing, setIsEditing] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const { id } = useParams();

    useEffect(() => {
        const fetchCategories = async () => {
            try {
                const response = await fetch('https://shopmate-sbxu.onrender.com/categories');
                if (!response.ok) {
                    throw new Error('Failed to fetch categories');
                }
                const data = await response.json();
                setCategories(data.categories);
            } catch (err) {
                setError(err.message);
            }
        };

        fetchCategories();
    }, []);

    useEffect(() => {
        if (id) {
            const fetchCategory = async () => {
                try {
                    const response = await fetch(`https://shopmate-sbxu.onrender.com/categories/${id}`);
                    if (!response.ok) {
                        throw new Error('Failed to fetch category');
                    }
                    const data = await response.json();
                    setCategory(data.category);
                    setIsEditing(true);
                } catch (err) {
                    setError(err.message);
                }
            };

            fetchCategory();
        }
    }, [id]);

    const handleChange = (e) => {
        setCategory({ ...category, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const method = isEditing ? 'PUT' : 'POST';
            const url = isEditing
                ? `https://shopmate-sbxu.onrender.com/categories/${id}`
                : 'https://shopmate-sbxu.onrender.com/categories';

            const response = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(category),
            });
            if (!response.ok) {
                throw new Error(isEditing ? 'Failed to update category' : 'Failed to add category');
            }
            navigate('/admin/categories');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDelete = async (categoryId) => {
        try {
            const response = await fetch(`https://shopmate-sbxu.onrender.com/categories/${categoryId}`, {
                method: 'DELETE',
            });
            if (!response.ok) {
                throw new Error('Failed to delete category');
            }
            setCategories(categories.filter(c => c.id !== categoryId));
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="container mx-auto px-4 py-8">
            <h2 className="text-2xl font-bold mb-4 text-black">{isEditing ? 'Edit Category' : 'Add Category'}</h2>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <form onSubmit={handleSubmit} className="bg-white p-6 rounded shadow-md border border-black mb-8">
                <div className="mb-4">
                    <label htmlFor="name" className="block text-black font-bold mb-2">Category Name</label>
                    <input
                        id="name"
                        name="name"
                        type="text"
                        value={category.name}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <button
                    type="submit"
                    className={`text-white px-4 py-2 rounded ${isEditing ? 'bg-orange-500 hover:bg-orange-600' : 'bg-green-500 hover:bg-green-600'}`}
                >
                    {isEditing ? 'Update Category' : 'Add Category'}
                </button>
            </form>

            <h2 className="text-2xl font-bold mb-4 text-black">Manage Categories</h2>
            <table className="w-full border-collapse border border-black">
                <thead>
                    <tr>
                        <th className="border border-black px-4 py-2">ID</th>
                        <th className="border border-black px-4 py-2">Name</th>
                        <th className="border border-black px-4 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {categories.map(c => (
                        <tr key={c.id}>
                            <td className="border border-black px-4 py-2">{c.id}</td>
                            <td className="border border-black px-4 py-2">{c.name}</td>
                            <td className="border border-black px-4 py-2">
                                <button
                                    onClick={() => navigate(`/admin/categories/edit/${c.id}`)}
                                    className="bg-orange-500 text-white px-4 py-2 rounded mr-2 hover:bg-orange-600"
                                >
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleDelete(c.id)}
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

export default CategoryManagement;
