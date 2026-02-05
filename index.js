import express, { json } from "express";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import "dotenv/config";
import cors from "cors";
import Stripe from "stripe";
import SSLCommerzPayment from "sslcommerz-lts";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();
const port = 3000;
const stripe = new Stripe(process.env.STRIPE_SERECT_KEY);

app.use(
  cors({
    origin: ["http://localhost:5173", "https://furniture-cc4d0.web.app/"],
    credentials: true,
  }),
);
app.use(cookieParser());

const uri = process.env.URI;

console.log(`8888888888888 ${uri}`);

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// create end point URL
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

// webhook
app.post(
  "/webhooks",
  express.raw({ type: "application/json" }),
  async (request, response) => {
    let event;
    if (endpointSecret) {
      // Get the signature sent by Stripe
      const signature = request.headers["stripe-signature"];
      try {
        event = stripe.webhooks.constructEvent(
          request.body,
          signature,
          endpointSecret,
        );
      } catch (err) {
        console.log(`⚠️ Webhook signature verification failed.`, err.message);
        return response.sendStatus(400);
      }

      // Handle the event
      switch (event.type) {
        case "payment_intent.succeeded":
          const paymentIntent = event.data.object;
          // Then define and call a method to handle the successful payment intent.
          // handlePaymentIntentSucceeded(paymentIntent);
          break;
        case "payment_method.attached":
          const paymentMethod = event.data.object;
          // Then define and call a method to handle the successful attachment of a PaymentMethod.
          // handlePaymentMethodAttached(paymentMethod);
          break;
        case "checkout.session.completed":
          const checkoutMethod = event.data.object;
          console.log(checkoutMethod);

          try {
            await client.connect();
            // Send a ping to confirm a successful connection
            await client.db("admin").command({ ping: 1 });

            const DB = client.db("furniture");
            const orderCollection = DB.collection("orderCollection");
            const cartCollection = DB.collection("cartCollection");

            const metaData = checkoutMethod.metadata;
            console.log(metaData);

            const updateResult = await orderCollection.updateOne(
              {
                _id: new ObjectId(metaData.orderID),
              },
              {
                $set: {
                  paymentStatus: "completed",
                },
              },
            );

            // console.log(updateResult);

            const cartIds = JSON.parse(metaData.cartIDs);
            const objectIDs = cartIds.map((item) => new ObjectId(item));

            // console.log(objectIDs);
            const deletedResult = await cartCollection.deleteMany({
              _id: {
                $in: objectIDs,
              },
            });

            console.log(deletedResult);

            // const payload = {
            //   ...metaData,
            //   Date: Date.now(),
            //   cartData: JSON.parse(metaData.cartData),
            // };
            // console.log(payload);
            // const result = await orderCollection.insertOne(payload);

            // console.log(result);

            // const arrayOfIds = JSON.parse(metaData.cartData).map(
            //   (item) => new ObjectId(item.cartID)
            // );

            // console.log(arrayOfIds);
          } catch (error) {
            console.log(error);
          }

          break;
        // ... handle other event types
        default:
          console.log(`Unhandled event type ${event.type}`);
      }

      // Return a response to acknowledge receipt of the event
      response.json({ received: true });
    }
  },
);

app.use(express.json());

// security
// app.post("/jwt", (req, res) => {
//   const data = req.body;

//   const token = jwt.sign({ email: data.email }, process.env.JWT_SECRET_KEY, {
//     expiresIn: "1h",
//   });

//   res.cookie("token", token, {
//     httpOnly: true,
//     path: "/",
//     secure: false,
//     sameSite: "lax",
//     maxAge:3600000,
//   }).send({success:true})
//   console.log(token);
// });
app.post("/jwt", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET_KEY, {
    expiresIn: "1h",
  });

  res
    .cookie("token", token, {
      httpOnly: true,
      path: "/",
      // secure: false, // Localhost এর জন্য false, live এ true করতে হবে
      // sameSite: "lax", // sameSite: "lax",  // for localhost - "lax" , for production - "None" ,
      secure: true, 
      sameSite: "None",
      maxAge: 36000000,
    })
    .json({ success: true, token });

  console.log("JWT Token:", token);
});

app.post("/log-out", async (req, res) => {
  res.clearCookie("token").send({ success: true });
});

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  console.log(token);
  if (!token) {
    return res.status(401).json({ error: "Unauthorized, token missing" });
  }

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized, token invalid" });
    }
    req.user = decoded;
    next();
  });
};

const verifyAdmin = async (req, res, next) => {
  console.log(req.user.email);
  const DB = client.db("furniture");
  const userCollection = DB.collection("userCollection");

  const response = await userCollection.findOne({ email: req.user.email });

  if (response.role == "admin") {
    next();
  } else {
    return res.status(401).send({ error: "unauthorized request" });
  }
  console.log(response);
};

app.get("/isAdmin/:email", async (req, res) => {
  const DB = client.db("furniture");
  const userCollection = DB.collection("userCollection");

  const response = await userCollection.findOne({ email: req.params.email });

  if (response?.role === "admin") {
    return res.send({ isAdmin: true });
  } else {
    return res.send({ isAdmin: false });
  }
});

app.get("/", (req, res) => {
  res.send("hello world");
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });

    const DB = client.db("furniture");
    const userCollection = DB.collection("userCollection");
    const categoryCollection = DB.collection("categoryCollection");
    const ProductCollection = DB.collection("ProductCollection");
    const cartCollection = DB.collection("cartCollection");
    const orderCollection = DB.collection("orderCollection");

    app.post("/user", async (req, res) => {
      const body = req.body;
      console.log(body);

      const { name, email } = req.body;

      if (!name || !email) {
        return res.status(400).json({ message: "name & email is required" });
      }

      const userData = await userCollection.findOne({ email: email });
      console.log(userData);

      if (userData) {
        return res
          .status(200)
          .json({ message: "User Already Exists", user: userData });
      }

      try {
        const result = await userCollection.insertOne({ name, email });
        res.status(201).send(result);
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    });

    app.get("/user", verifyToken, verifyAdmin, async (req, res) => {
      const response = await userCollection.find().toArray();
      res.send(response);
    });

    app.patch("/user/make-admin/:email",  async (req, res) => {
      const { email } = req.params;
      const result = await userCollection.updateOne(
        {
          email: email,
        },
        {
          $set: {
            role: "admin",
          },
        },
      );

      res.send(result);
    });

    app.post("/category", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const data = req.body;
        console.log(data);
        const { name, image } = req.body;

        const result = await categoryCollection.insertOne({ name, image });
        res.status(201).send(result);
      } catch (error) {
        res.status(500).json(error.message);
      }
    });

    app.get("/category", async (req, res) => {
      try {
        const result = await categoryCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    app.delete("/category/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;

      try {
        const result = await categoryCollection.deleteOne({
          _id: new ObjectId(id),
        });
        console.log(result);
        res.status(200).json(result);
      } catch (error) {
        res.status(500).json(error);
      }
    });

    app.post("/product", verifyToken, verifyAdmin, async (req, res) => {
      const data = req.body;

      try {
        const result = await ProductCollection.insertOne(data);
        console.log(result);
        res.status(201).json(result);
      } catch (error) {
        res.status(500).send(error);
      }
    });

    app.get("/product", async (req, res) => {
      try {
        const result = await ProductCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    app.get("/product/:id", async (req, res) => {
      const { id } = req.params;

      console.log(id);
      try {
        const result = await ProductCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
        console.log(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    app.put("/product/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;

      const query = { _id: new ObjectId(id) };
      const dataobject = req.body;

      const updateDoc = {
        $set: dataobject,
      };

      try {
        const result = await ProductCollection.updateOne(query, updateDoc);
        console.log(result);
        return res.send(result);
      } catch (error) {
        res.status(500).send(error);
      }
    });

    app.delete("/product/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;
      try {
        const response = await ProductCollection.deleteOne({
          _id: new ObjectId(id),
        });
        console.log(response);
        res.status(200).json(response);
      } catch (error) {
        res.status(500).json(error);
      }
    });

    app.post("/cart", verifyToken, async (req, res) => {
      const { productID, email, quantity } = req.body;

      if (!productID)
        return res.status(400).json({ error: "productID is required" });
      if (!email) return res.status(400).json({ error: "email is required" });
      if (!quantity)
        return res.status(400).json({ error: "quantity is required" });

      try {
        const previousCart = await cartCollection.findOne({
          productID: productID,
          email: email,
        });
        console.log(previousCart);

        if (previousCart) {
          return res.send({ error: "Product is already in cart " });
        }

        const result = await cartCollection.insertOne({
          productID,
          email,
          quantity,
        });
        res.send(result);
      } catch (error) {
        res.status(500).json(error.message);
      }
    });

    // app.get("/cart/:email",verifyToken, async (req, res) => {
    //   const email = req.params.email;

    //    if (email !== req.user.email) {
    //      return res
    //        .status(401)
    //        .json({
    //          error: "UnAuthorized Access , plead login from original account",
    //        });
    //    }

    //   try {
    //     const result = await cartCollection
    //       .aggregate([
    //         {
    //           $match: {
    //             email: email,
    //           },
    //         },
    //         {
    //           $addFields: {
    //             productObjID: {
    //               $toObjectId: "$productID",
    //             },
    //           },
    //         },
    //         {
    //           $lookup: {
    //             from: "ProductCollection",
    //             localField: "productObjID",
    //             foreignField: "_id",
    //             as: "productInfo",
    //           },
    //         },
    //         {
    //           $unwind: "$productInfo",
    //         },
    //         {
    //           $project: {
    //             _id: 1,
    //             email: 1,
    //             quantity: 1,
    //             productInfo: 1,
    //           },
    //         },
    //       ])
    //       .toArray();

    //     // const result = await cartCollection.find({email:email}).toArray()
    //     res.json(result);
    //   } catch (error) {
    //     res.status(500).json(error.message);
    //   }
    // });

    app.get("/cart/:email", verifyToken, async (req, res) => {
      const email = req.params.email;

      if (email !== req.user?.email) {
        return res.status(401).send({
          error: "Unauthorized Access, please login from original account",
        });
      }

      try {
        const result = await cartCollection
          .aggregate([
            { $match: { email } },
            { $addFields: { productObjID: { $toObjectId: "$productID" } } },
            {
              $lookup: {
                from: "ProductCollection",
                localField: "productObjID",
                foreignField: "_id",
                as: "productInfo",
              },
            },
            { $unwind: "$productInfo" },
            { $project: { _id: 1, email: 1, quantity: 1, productInfo: 1 } },
          ])
          .toArray();

        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    app.patch("/cart/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const { quantity } = req.body;
      try {
        const result = await cartCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { quantity } },
        );
        res.send(result);
      } catch (error) {
        console.log(error);
      }
    });

    app.delete("/cart/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      try {
        const response = await cartCollection.deleteOne({
          _id: new ObjectId(id),
        });
        console.log(response);
        res.status(200).json(response);
      } catch (error) {
        res.status(500).json(error);
      }
    });

    app.delete("/cart", verifyToken, async (req, res) => {
      try {
        const response = await cartCollection.deleteMany();
        res.send(response);
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // payment Methods

    app.post("/order", async (req, res) => {
      const data = req.body;

      const newCartData = req.body.cartData.map((item) => ({
        cartID: item._id,
        productID: item.productInfo._id,
        buyingPrice: item.productInfo.offeredPrice,
        quantity: item.quantity,
      }));
      const cartIDs = JSON.stringify(data.cartData.map((item) => item._id));

      const orderPayload = {
        ...data,
        cartData: newCartData,
        paymentStatus: "pending",
        orderStatus: "pending",
        orderDate: Date.now(),
      };

      const orderResult = await orderCollection.insertOne(orderPayload);

      if (orderResult.insertedId) {
        if (data.paymentMethod == "COD") {
          const cartObjectIds = data.cartData.map(
            (item) => new ObjectId(item._id),
          );

          await cartCollection.deleteMany({
            _id: { $in: cartObjectIds },
          });

          return res.json({
            url: "http://localhost:5173/user/myOrder",
          });
        } else if (data.paymentMethod == "Stripe") {
          const products = await Promise.all(
            data.cartData.map(async (item) => {
              const productInfo = await ProductCollection.findOne({
                _id: new ObjectId(item.productInfo._id),
              });
              // console.log(productInfo);
              return {
                price_data: {
                  currency: "usd",
                  product_data: {
                    name: productInfo.title,
                    images: productInfo.imageUrls,
                  },
                  unit_amount: productInfo.offeredPrice * 100,
                },
                quantity: item.quantity,
              };
            }),
          );

          console.log(cartIDs);

          const session = await stripe.checkout.sessions.create({
            line_items: products,
            metadata: {
              orderID: String(orderResult.insertedId),
              cartIDs: cartIDs,
            },
            mode: "payment",
            success_url: "http://localhost:5173/success",
          });

          res.json({ url: session.url });
        } else if (data.paymentMethod == "SSL") {
          // ssl sandbox password: sandbox36967
          // userName:	jahirul;
          const store_id = process.env.SSL_STORE_ID;
          const store_passwd = process.env.SSL_STORE_PASS;
          const is_live = false; //true for live, false for sandbox

          const initialValue = 0;
          const totalAmount = newCartData.reduce(
            (accumulator, currentValue) =>
              accumulator +
              parseFloat(currentValue.buyingPrice * currentValue.quantity),
            initialValue,
          );

          console.log(totalAmount);
          const encodedUrl = encodeURIComponent(cartIDs);
          console.log(encodedUrl);

          const data = {
            total_amount: totalAmount * 122,
            currency: "BDT",
            tran_id: "REF123", // use unique tran_id for each api call
            success_url:
              `http://localhost:3000/success/${orderResult.insertedId}?cartIds=` +
              encodedUrl,
            fail_url: `http://localhost:3000/fail/${orderResult.insertedId}`,
            cancel_url: "http://localhost:3000/cancel",
            ipn_url: "http://localhost:3000/ipn",
            shipping_method: "Courier",
            product_name: "Computer.",
            product_category: "Electronic",
            product_profile: "general",
            cus_name: "Customer Name",
            cus_email: "customer@example.com",
            cus_add1: "Dhaka",
            cus_add2: "Dhaka",
            cus_city: "Dhaka",
            cus_state: "Dhaka",
            cus_postcode: "1000",
            cus_country: "Bangladesh",
            cus_phone: "01711111111",
            cus_fax: "01711111111",
            ship_name: "Customer Name",
            ship_add1: "Dhaka",
            ship_add2: "Dhaka",
            ship_city: "Dhaka",
            ship_state: "Dhaka",
            ship_postcode: 1000,
            ship_country: "Bangladesh",
            value_a: JSON.stringify(cartIDs),
          };
          const sslcz = new SSLCommerzPayment(store_id, store_passwd, is_live);
          sslcz.init(data).then((apiResponse) => {
            // Redirect the user to payment gateway
            console.log(apiResponse);
            let GatewayPageURL = apiResponse.GatewayPageURL;
            res.json({ url: GatewayPageURL });
            console.log("Redirecting to: ", GatewayPageURL);
          });
        } else {
          res.send({ error: "please select a supported payment method " });
        }
      }
    });

    // ssl success api

    app.post("/success/:orderID", async (req, res) => {
      const { orderID } = req.params;
      console.log(orderID);

      console.log(req.query);

      const updateResult = await orderCollection.updateOne(
        {
          _id: new ObjectId(orderID),
        },
        {
          $set: {
            paymentStatus: "completed",
          },
        },
      );

      // const cartIdsString =  req.query.cartIds
      const cartIds = JSON.parse(req.query.cartIds);
      const objectIDs = cartIds.map((item) => new ObjectId(item));

      console.log(objectIDs);

      const deletedResult = await cartCollection.deleteMany({
        _id: {
          $in: objectIDs,
        },
      });

      console.log(deletedResult);

      return res.redirect("http://localhost:5173/");
    });

    app.post("/fail/:orderID", async (req, res) => {
      const { orderID } = req.params;
      console.log(orderID);

      const deletedResult = await orderCollection.deleteOne({
        _id: new ObjectId(orderID),
      });

      console.log(deletedResult);

      return res.redirect("http://localhost:5173/");
    });

    //  stripe api==========================
    app.post("/create-checkout-session", async (req, res) => {
      const data = req.body;

      console.log(data);

      const cartData = data?.cartData?.map((item) => ({
        email: item.email,
        quantity: item.quantity,
        buyingPrice: item.productInfo.offeredPrice,
        productID: item.productInfo._id,
        cartID: item._id,
      }));

      const metaData = { ...data, cartData };

      const products = await Promise.all(
        data.cartData.map(async (item) => {
          const productInfo = await ProductCollection.findOne({
            _id: new ObjectId(item.productInfo._id),
          });
          return {
            price_data: {
              currency: "usd",
              product_data: {
                name: productInfo.title,
                images: productInfo.imageUrls,
              },
              unit_amount: productInfo.offeredPrice * 100,
            },
            quantity: item.quantity,
          };
        }),
      );

      console.log(data);
      console.log(products);
      const session = await stripe.checkout.sessions.create({
        line_items: products,
        metadata: {
          ...metaData,
          cartData: JSON.stringify(metaData.cartData),
        },
        mode: "payment",
        success_url: "http://localhost:5173/success",
      });

      res.json({ url: session.url });
    });

    app.get("/myOrders/:email", verifyToken, async (req, res) => {
      const { email } = req.params;

      console.log(`email ${email}`);

      try {
        const response = await orderCollection.find({ email: email }).toArray();

        const product = await Promise.all(
          response.map(async (item) => {
            console.log(item);

            const productInfo = await Promise.all(
              item.cartData.map(async (item) => {
                const result = await ProductCollection.findOne({
                  _id: new ObjectId(item.productID),
                });

                return {
                  ...result,
                  quantity: item.quantity,
                  buyingPrice: item.buyingPrice,
                };
              }),
            );

            return {
              ...item,
              products: productInfo,
            };
          }),
        );

        console.log(product);

        res.send(product);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }

      console.log(email);
    });

    app.get("/all-orders", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const response = await orderCollection.find().toArray();

        const product = await Promise.all(
          response.map(async (item) => {
            console.log(item);

            const productInfo = await Promise.all(
              item.cartData.map(async (item) => {
                const result = await ProductCollection.findOne({
                  _id: new ObjectId(item.productID),
                });

                return {
                  ...result,
                  quantity: item.quantity,
                  buyingPrice: item.buyingPrice,
                };
              }),
            );

            return {
              ...item,
              products: productInfo,
            };
          }),
        );

        console.log(product);

        res.send(product);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    app.get("/all-orders/:id", verifyToken, verifyAdmin, async (req, res) => {
      const { id } = req.params;

      try {
        const response = await orderCollection.findOne({
          _id: new ObjectId(id),
        });

        const productInfo = await Promise.all(
          response.cartData.map(async (item) => {
            const result = await ProductCollection.findOne({
              _id: new ObjectId(item.productID),
            });

            return {
              ...result,
              quantity: item.quantity,
              buyingPrice: item.buyingPrice,
            };
          }),
        );

        res.send({
          ...response,
          products: productInfo,
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }

      console.log(email);
    });

    app.patch("/order/:id", verifyToken, async (req, res) => {
      const id = req.params.id;

      const result = await orderCollection.updateOne(
        {
          _id: new ObjectId(id),
        },
        {
          $set: {
            orderStatus: "Delivered",
            paymentStatus: "Completed",
          },
        },
      );

      res.send(result);
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`server is running at http://localhost:${port}`);
});
