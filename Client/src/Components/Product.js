import React from "react";
import "../Components/Product.css";
import { useStateValue } from "../ContextAPI/StateProvider";
import CurrencyFormat from "react-currency-format";

function Product({ id, title, image, price, rating }) {
  const [{ basket }, dispatch] = useStateValue();
  const addToBasket = () => {
    //add item to basket
    dispatch({
      type: "ADD_TO_BASKET",
      item: {
        id,
        title,
        image,
        price,
        rating,
      },
    });
  };
  return (
    <div className="product" onClick={addToBasket}>

      <CurrencyFormat
        renderText={(price) => (
          <>
            <img src={image} alt="" />
            <div className="product_info">
              <p className="title">{title}</p>
              <p className="product_price">
                <span> </span>
                <span>{price}</span>
              </p>
              <div className="product_rating">
                {Array(rating)
                  .fill()
                  .map((_) => (
                    <p>🌟</p>
                  ))}
              </div>
            </div>
          </>
        )}
        decimalScale={2}
        value={price}
        displayType={"text"}
        thousandSeparator={true}
        prefix={"$: "}
      />
      <div className="button">
        <p className="click_button">ADD TO CART</p>
      </div>
    </div>
  );
}

export default Product;