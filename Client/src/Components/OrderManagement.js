import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const OrderManagement = () => {
    const [orders, setOrders] = useState([]);
    const [order, setOrder] = useState({ status: '' });
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const { id } = useParams();

    useEffect(() => {
        const fetchOrders = async () => {
            try {
                const response = await fetch('https://shopmate-sbxu.onrender.com/orders');
                if (!response.ok) {
                    throw new Error('Failed to fetch orders');
                }
                const data = await response.json();
                setOrders(data.orders);
            } catch (err) {
                setError(err.message);
            }
        };

        fetchOrders();
    }, []);

    useEffect(() => {
        if (id) {
            const fetchOrder = async () => {
                try {
                    const response = await fetch(`https://shopmate-sbxu.onrender.com/orders/${id}`);
                    if (!response.ok) {
                        throw new Error('Failed to fetch order');
                    }
                    const data = await response.json();
                    setOrder(data.order);
                } catch (err) {
                    setError(err.message);
                }
            };

            fetchOrder();
        }
    }, [id]);

    const handleChange = (e) => {
        setOrder({ ...order, [e.target.name]: e.target.value });
    };

    const handleUpdate = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch(`https://shopmate-sbxu.onrender.com/orders/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(order),
            });
            if (!response.ok) {
                throw new Error('Failed to update order');
            }
            navigate('/admin/orders');
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="container mx-auto px-4 py-8">
            <h2 className="text-2xl font-bold mb-4 text-black">Manage Orders</h2>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            {id && (
                <form onSubmit={handleUpdate} className="bg-white p-6 rounded shadow-md border border-black mb-8">
                    <div className="mb-4">
                        <label htmlFor="status" className="block text-black font-bold mb-2">Order Status</label>
                        <input
                            id="status"
                            name="status"
                            type="text"
                            value={order.status}
                            onChange={handleChange}
                            className="w-full border border-black rounded px-3 py-2"
                        />
                    </div>
                    <button
                        type="submit"
                        className="text-white px-4 py-2 rounded bg-orange-500 hover:bg-orange-600"
                    >
                        Update Order
                    </button>
                </form>
            )}
            <table className="w-full border-collapse border border-black">
                <thead>
                    <tr>
                        <th className="border border-black px-4 py-2">ID</th>
                        <th className="border border-black px-4 py-2">Status</th>
                        <th className="border border-black px-4 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {orders.map(o => (
                        <tr key={o.id}>
                            <td className="border border-black px-4 py-2">{o.id}</td>
                            <td className="border border-black px-4 py-2">{o.status}</td>
                            <td className="border border-black px-4 py-2">
                                <button
                                    onClick={() => navigate(`/admin/orders/edit/${o.id}`)}
                                    className="bg-orange-500 text-white px-4 py-2 rounded mr-2 hover:bg-orange-600"
                                >
                                    Edit
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default OrderManagement;
