import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [user, setUser] = useState({ name: '', email: '', role: '' });
    const [isEditing, setIsEditing] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const { id } = useParams();

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await fetch('https://shopmate-sbxu.onrender.com/users');
                if (!response.ok) {
                    throw new Error('Failed to fetch users');
                }
                const data = await response.json();
                setUsers(data.users);
            } catch (err) {
                setError(err.message);
            }
        };

        fetchUsers();
    }, []);

    useEffect(() => {
        if (id) {
            const fetchUser = async () => {
                try {
                    const response = await fetch(`https://shopmate-sbxu.onrender.com/users/${id}`);
                    if (!response.ok) {
                        throw new Error('Failed to fetch user');
                    }
                    const data = await response.json();
                    setUser(data.user);
                    setIsEditing(true);
                } catch (err) {
                    setError(err.message);
                }
            };

            fetchUser();
        }
    }, [id]);

    const handleChange = (e) => {
        setUser({ ...user, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const method = isEditing ? 'PUT' : 'POST';
            const url = isEditing
                ? `https://shopmate-sbxu.onrender.com/users/${id}`
                : 'https://shopmate-sbxu.onrender.com/users';

            const response = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(user),
            });
            if (!response.ok) {
                throw new Error(isEditing ? 'Failed to update user' : 'Failed to add user');
            }
            navigate('/admin/users');
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDelete = async (userId) => {
        try {
            const response = await fetch(`https://shopmate-sbxu.onrender.com/users/${userId}`, {
                method: 'DELETE',
            });
            if (!response.ok) {
                throw new Error('Failed to delete user');
            }
            setUsers(users.filter(u => u.id !== userId));
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="container mx-auto px-4 py-8">
            <h2 className="text-2xl font-bold mb-4 text-black">{isEditing ? 'Edit User' : 'Add User'}</h2>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <form onSubmit={handleSubmit} className="bg-white p-6 rounded shadow-md border border-black mb-8">
                <div className="mb-4">
                    <label htmlFor="name" className="block text-black font-bold mb-2">Name</label>
                    <input
                        id="name"
                        name="name"
                        type="text"
                        value={user.name}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="email" className="block text-black font-bold mb-2">Email</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        value={user.email}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="role" className="block text-black font-bold mb-2">Role</label>
                    <input
                        id="role"
                        name="role"
                        type="text"
                        value={user.role}
                        onChange={handleChange}
                        className="w-full border border-black rounded px-3 py-2"
                    />
                </div>
                <button
                    type="submit"
                    className={`text-white px-4 py-2 rounded ${isEditing ? 'bg-orange-500 hover:bg-orange-600' : 'bg-green-500 hover:bg-green-600'}`}
                >
                    {isEditing ? 'Update User' : 'Add User'}
                </button>
            </form>

            <h2 className="text-2xl font-bold mb-4 text-black">Manage Users</h2>
            <table className="w-full border-collapse border border-black">
                <thead>
                    <tr>
                        <th className="border border-black px-4 py-2">ID</th>
                        <th className="border border-black px-4 py-2">Name</th>
                        <th className="border border-black px-4 py-2">Email</th>
                        <th className="border border-black px-4 py-2">Role</th>
                        <th className="border border-black px-4 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {users.map(u => (
                        <tr key={u.id}>
                            <td className="border border-black px-4 py-2">{u.id}</td>
                            <td className="border border-black px-4 py-2">{u.name}</td>
                            <td className="border border-black px-4 py-2">{u.email}</td>
                            <td className="border border-black px-4 py-2">{u.role}</td>
                            <td className="border border-black px-4 py-2">
                                <button
                                    onClick={() => navigate(`/admin/users/edit/${u.id}`)}
                                    className="bg-orange-500 text-white px-4 py-2 rounded mr-2 hover:bg-orange-600"
                                >
                                    Edit
                                </button>
                                <button
                                    onClick={() => handleDelete(u.id)}
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

export default UserManagement;
