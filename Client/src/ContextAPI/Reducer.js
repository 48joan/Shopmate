export const initialState = {
    basket: [],
    user: null, // initially no user is logged in
    term: null,
    discount: 0,
    orders: [], // Added for order management
    products: [], // Added for product management
    categories: [], // Added for category management
};

// Define action types for the reducer
export const actionTypes = {
    SET_SEARCH_TERM: "SET_SEARCH_TERM",
    ADD_TO_BASKET: "ADD_TO_BASKET",
    REMOVE_FROM_BASKET: "REMOVE_FROM_BASKET",
    APPLY_DISCOUNT: "APPLY_DISCOUNT",
    SET_USER: "SET_USER",
    EMPTY_BASKET: "EMPTY_BASKET",
    SET_ORDERS: "SET_ORDERS",
    ADD_PRODUCT: "ADD_PRODUCT",
    UPDATE_PRODUCT: "UPDATE_PRODUCT",
    DELETE_PRODUCT: "DELETE_PRODUCT",
    ADD_CATEGORY: "ADD_CATEGORY",
    DELETE_CATEGORY: "DELETE_CATEGORY",
};

// Reducer function that handles various state updates
function reducer(state, action) {
    switch (action.type) {
        case actionTypes.SET_USER:
            return {
                ...state,
                user: action.user // user will have isAdmin property
            };
        
        case actionTypes.SET_SEARCH_TERM:
            return {
                ...state,
                term: action.term,
            };

        case actionTypes.ADD_TO_BASKET:
            return {
                ...state,
                basket: [...state.basket, action.item]
            };

        case actionTypes.REMOVE_FROM_BASKET:
            let newBasket = [...state.basket];
            const index = state.basket.findIndex(
                (basketItem) => basketItem.id === action.id
            );
            if (index >= 0) {
                newBasket.splice(index, 1); // remove item from basket
            } else {
                console.warn(`Can't remove product with id: ${action.id}`);
            }
            return {
                ...state,
                basket: newBasket,
            };

        case actionTypes.APPLY_DISCOUNT:
            return {
                ...state,
                discount: action.discount,
            };

        case actionTypes.SET_ORDERS:
            return {
                ...state,
                orders: action.orders,
            };

        case actionTypes.ADD_PRODUCT:
            return {
                ...state,
                products: [...state.products, action.product],
            };

        case actionTypes.UPDATE_PRODUCT:
            return {
                ...state,
                products: state.products.map(product => 
                    product.id === action.product.id ? action.product : product
                ),
            };

        case actionTypes.DELETE_PRODUCT:
            return {
                ...state,
                products: state.products.filter(product => product.id !== action.id),
            };

        case actionTypes.ADD_CATEGORY:
            return {
                ...state,
                categories: [...state.categories, action.category],
            };

        case actionTypes.DELETE_CATEGORY:
            return {
                ...state,
                categories: state.categories.filter(category => category.id !== action.id),
            };

        default:
            return state;
    }
}

export default reducer;
