from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import hmac
import hashlib
import base64
import requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI()
# १. CORS Middleware यहाँ थप्नुहोस् (router भन्दा माथि)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://rumba-frontend.onrender.com", 
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# २. तपाईँको राउटर सेटिङ
api_router = APIRouter(prefix="/api")

# यहाँ तपाईँको रुटहरू (routes) होलान्...
# api_router.get("/cart")...

app.include_router(api_router)

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ALGORITHM = "HS256"

# Storage Configuration
STORAGE_URL = "https://integrations.emergentagent.com/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = os.environ.get("APP_NAME", "rumba-tailor")
storage_key = None

# ============ Models ============
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class CategoryCreate(BaseModel):
    name: str
    description: Optional[str] = None

class Category(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created_at: str

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    category_id: str
    image_url: Optional[str] = None
    stock: int = 0
    fabric_type: Optional[str] = None
    available_sizes: Optional[List[str]] = None

class Product(BaseModel):
    id: str
    name: str
    description: str
    price: float
    category_id: str
    image_url: Optional[str] = None
    stock: int
    fabric_type: Optional[str] = None
    available_sizes: Optional[List[str]] = None
    created_at: str

class CartItem(BaseModel):
    product_id: str
    quantity: int
    size: Optional[str] = None

class CartItemResponse(BaseModel):
    id: str
    product_id: str
    product_name: str
    product_price: float
    product_image: Optional[str]
    quantity: int
    size: Optional[str] = None

class TailorMeasurements(BaseModel):
    chest: Optional[float] = None
    waist: Optional[float] = None
    length: Optional[float] = None
    shoulder: Optional[float] = None
    sleeve_length: Optional[float] = None
    custom_notes: Optional[str] = None

class OrderCreate(BaseModel):
    customer_name: str
    customer_email: EmailStr
    customer_phone: str
    delivery_address: str
    payment_gateway: str
    measurements: Optional[TailorMeasurements] = None

class Order(BaseModel):
    id: str
    customer_name: str
    customer_email: str
    customer_phone: str
    delivery_address: str
    items: List[dict]
    total_amount: float
    payment_gateway: str
    payment_status: str
    order_status: str
    transaction_uuid: str
    measurements: Optional[dict] = None
    created_at: str

# ============ Auth Helper Functions ============
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============ Storage Functions ============
def init_storage():
    global storage_key
    if storage_key:
        return storage_key
    try:
        resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
        resp.raise_for_status()
        storage_key = resp.json()["storage_key"]
        return storage_key
    except Exception as e:
        logging.error(f"Storage init failed: {e}")
        return None

def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    if not key:
        raise HTTPException(status_code=500, detail="Storage not initialized")
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data,
        timeout=120
    )
    resp.raise_for_status()
    return resp.json()

def get_object(path: str) -> tuple:
    key = init_storage()
    if not key:
        raise HTTPException(status_code=500, detail="Storage not initialized")
    resp = requests.get(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key},
        timeout=60
    )
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")

# ============ eSewa Payment Functions ============
def generate_esewa_signature(total_amount: str, transaction_uuid: str, product_code: str) -> str:
    secret_key = os.environ.get("ESEWA_SECRET_KEY")
    signature_string = f"total_amount={total_amount},transaction_uuid={transaction_uuid},product_code={product_code}"
    signature_bytes = hmac.new(
        secret_key.encode('utf-8'),
        signature_string.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature_bytes).decode('utf-8')

# ============ Startup Event ============
@app.on_event("startup")
async def startup():
    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@rumbatailor.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email}, {"_id": 0})
    if not existing:
        admin_id = str(uuid.uuid4())
        await db.users.insert_one({
            "id": admin_id,
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logging.info(f"Admin user created: {admin_email}")

        from fastapi import FastAPI, HTTPException
import os

# तपाईँको अगाडिको generate_esewa_signature फङ्सन यहाँ छ भनेर मानौँ...

@app.post("/api/payment/initiate/{order_id}")
async def initiate_esewa_payment(order_id: str, amount: float):
    try:
        # १. eSewa को लागि चाहिने Settings
        product_code = "EPAYTEST" # यो टेस्टिङको लागि हो
        
        # २. तपाईँले अघि देखाउनुभएको फङ्सन प्रयोग गरेर Signature बनाउने
        # (amount लाई string मा पठाउनु पर्छ)
        sig = generate_esewa_signature(str(amount), order_id, product_code)
        
        # ३. फ्रन्टइन्डलाई चाहिने सबै डाटा फिर्ता पठाउने
        return {
            "status": "success",
            "signature": sig,
            "product_code": product_code,
            "amount": amount,
            "transaction_uuid": order_id,
            "url": "https://rc.esewa.com.np/api/epay/main/v2/form"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.products.create_index("category_id")
    
    # Initialize storage
    try:
        init_storage()
        logging.info("Storage initialized")
    except Exception as e:
        logging.error(f"Storage init failed: {e}")
    
    # Write test credentials
    os.makedirs("/app/memory", exist_ok=True)
    with open("/app/memory/test_credentials.md", "w") as f:
        f.write(f"# Test Credentials\n\n")
        f.write(f"## Admin Account\n")
        f.write(f"- Email: {admin_email}\n")
        f.write(f"- Password: {admin_password}\n")
        f.write(f"- Role: admin\n\n")
        f.write(f"## Auth Endpoints\n")
        f.write(f"- POST /api/auth/login\n")
        f.write(f"- GET /api/auth/me\n")
        f.write(f"- POST /api/auth/logout\n")

# ============ Auth Routes ============
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email.lower()}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    await db.users.insert_one({
        "id": user_id,
        "email": user_data.email.lower(),
        "password_hash": hash_password(user_data.password),
        "name": user_data.name,
        "phone": user_data.phone,
        "address": user_data.address,
        "city": user_data.city,
        "role": "customer",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    user.pop("password_hash")
    return {"user": user, "message": "Registration successful"}

@api_router.post("/auth/login")
async def login(credentials: UserLogin, response: Response):
    user = await db.users.find_one({"email": credentials.email.lower()}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(user["id"], user["email"])
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86400,
        path="/"
    )
    user.pop("password_hash")
    return {"user": user, "token": access_token}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return user

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out"}

# ============ Admin Analytics Routes ============
@api_router.get("/admin/analytics")
async def get_analytics(request: Request):
    await get_current_user(request)
    
    # Count statistics
    total_orders = await db.orders.count_documents({})
    total_products = await db.products.count_documents({})
    total_customers = await db.users.count_documents({"role": "customer"})
    
    # Revenue calculation
    completed_orders = await db.orders.find(
        {"payment_status": "completed"},
        {"_id": 0, "total_amount": 1}
    ).to_list(10000)
    total_revenue = sum(order["total_amount"] for order in completed_orders)
    
    # Recent orders
    recent_orders = await db.orders.find(
        {},
        {"_id": 0}
    ).sort("created_at", -1).limit(5).to_list(5)
    
    # Low stock products
    low_stock = await db.products.find(
        {"stock": {"$lt": 10}},
        {"_id": 0}
    ).to_list(100)
    
    # Order status breakdown
    pending_orders = await db.orders.count_documents({"order_status": "pending"})
    in_progress_orders = await db.orders.count_documents({"order_status": "in_progress"})
    completed_orders_count = await db.orders.count_documents({"order_status": "completed"})
    
    return {
        "total_revenue": total_revenue,
        "total_orders": total_orders,
        "total_products": total_products,
        "total_customers": total_customers,
        "recent_orders": recent_orders,
        "low_stock_products": low_stock,
        "order_status": {
            "pending": pending_orders,
            "in_progress": in_progress_orders,
            "completed": completed_orders_count
        }
    }

@api_router.get("/admin/customers")
async def get_customers(request: Request):
    await get_current_user(request)
    
    customers = await db.users.find(
        {"role": "customer"},
        {"_id": 0, "password_hash": 0}
    ).sort("created_at", -1).to_list(1000)
    
    # Add order count for each customer
    for customer in customers:
        order_count = await db.orders.count_documents({"customer_email": customer["email"]})
        customer["order_count"] = order_count
    
    return customers

@api_router.get("/admin/customers/{customer_id}/orders")
async def get_customer_orders(customer_id: str, request: Request):
    await get_current_user(request)
    
    customer = await db.users.find_one({"id": customer_id}, {"_id": 0, "password_hash": 0})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    orders = await db.orders.find(
        {"customer_email": customer["email"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    
    return {"customer": customer, "orders": orders}

# ============ Profile Routes ============
@api_router.get("/profile")
async def get_profile(request: Request):
    user = await get_current_user(request)
    return user

@api_router.put("/profile")
async def update_profile(profile_data: dict, request: Request):
    user = await get_current_user(request)
    
    update_fields = {}
    if "name" in profile_data:
        update_fields["name"] = profile_data["name"]
    if "phone" in profile_data:
        update_fields["phone"] = profile_data["phone"]
    if "address" in profile_data:
        update_fields["address"] = profile_data["address"]
    if "city" in profile_data:
        update_fields["city"] = profile_data["city"]
    
    if update_fields:
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": update_fields}
        )
    
    updated_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0})
    return updated_user

@api_router.get("/profile/orders", response_model=List[Order])
async def get_user_orders(request: Request):
    user = await get_current_user(request)
    orders = await db.orders.find(
        {"customer_email": user["email"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    return orders

# ============ Category Routes ============
@api_router.post("/categories", response_model=Category)
async def create_category(category: CategoryCreate, request: Request):
    await get_current_user(request)
    category_id = str(uuid.uuid4())
    doc = {
        "id": category_id,
        "name": category.name,
        "description": category.description,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.categories.insert_one(doc)
    return Category(**doc)

@api_router.get("/categories", response_model=List[Category])
async def get_categories():
    categories = await db.categories.find({}, {"_id": 0}).to_list(100)
    return categories

@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, request: Request):
    await get_current_user(request)
    result = await db.categories.delete_one({"id": category_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}

# ============ Product Routes ============
@api_router.post("/products", response_model=Product)
async def create_product(product: ProductCreate, request: Request):
    await get_current_user(request)
    product_id = str(uuid.uuid4())
    doc = {
        "id": product_id,
        **product.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.products.insert_one(doc)
    return Product(**doc)

@api_router.get("/products", response_model=List[Product])
async def get_products(category_id: Optional[str] = None):
    query = {"category_id": category_id} if category_id else {}
    products = await db.products.find(query, {"_id": 0}).to_list(1000)
    return products

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, product: ProductCreate, request: Request):
    await get_current_user(request)
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": product.model_dump()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    updated = await db.products.find_one({"id": product_id}, {"_id": 0})
    return Product(**updated)

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, request: Request):
    await get_current_user(request)
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted"}

# ============ Upload Route ============
@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...), request: Request = None):
    if request:
        await get_current_user(request)
    
    ext = file.filename.split(".")[-1] if "." in file.filename else "bin"
    path = f"{APP_NAME}/products/{uuid.uuid4()}.{ext}"
    data = await file.read()
    result = put_object(path, data, file.content_type or "application/octet-stream")
    
    file_id = str(uuid.uuid4())
    await db.files.insert_one({
        "id": file_id,
        "storage_path": result["path"],
        "original_filename": file.filename,
        "content_type": file.content_type,
        "size": result["size"],
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    return {"file_id": file_id, "path": result["path"], "url": f"/api/files/{result['path']}"}

@api_router.get("/files/{path:path}")
async def get_file(path: str):
    record = await db.files.find_one({"storage_path": path, "is_deleted": False}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="File not found")
    data, content_type = get_object(path)
    return Response(content=data, media_type=record.get("content_type", content_type))

# ============ Cart Routes ============
@api_router.post("/cart")
async def add_to_cart(item: CartItem, request: Request, response: Response):
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())
    
    product = await db.products.find_one({"id": item.product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    existing = await db.cart_items.find_one({
        "session_id": session_id,
        "product_id": item.product_id
    }, {"_id": 0})
    
    if existing:
        await db.cart_items.update_one(
            {"session_id": session_id, "product_id": item.product_id},
            {"$set": {"quantity": item.quantity, "size": item.size}}
        )
    else:
        await db.cart_items.insert_one({
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "product_id": item.product_id,
            "quantity": item.quantity,
            "size": item.size,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        max_age=2592000,
        path="/",
        samesite="lax",
        httponly=False
    )
    return {"message": "Item added to cart", "session_id": session_id}

@api_router.get("/cart", response_model=List[CartItemResponse])
async def get_cart(request: Request):
    session_id = request.cookies.get("session_id")
    logging.info(f"Get cart called with session_id: {session_id}")
    
    if not session_id:
        logging.info("No session_id found, returning empty cart")
        return []
    
    cart_items = await db.cart_items.find({"session_id": session_id}, {"_id": 0}).to_list(100)
    logging.info(f"Found {len(cart_items)} cart items for session {session_id}")
    
    response_items = []
    
    for item in cart_items:
        product = await db.products.find_one({"id": item["product_id"]}, {"_id": 0})
        if product:
            response_items.append(CartItemResponse(
                id=item["id"],
                product_id=item["product_id"],
                product_name=product["name"],
                product_price=product["price"],
                product_image=product.get("image_url"),
                quantity=item["quantity"],
                size=item.get("size")
            ))
    
    logging.info(f"Returning {len(response_items)} response items")
    return response_items

@api_router.delete("/cart/{item_id}")
async def remove_from_cart(item_id: str, request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=404, detail="Cart not found")
    
    result = await db.cart_items.delete_one({"id": item_id, "session_id": session_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item removed"}

@api_router.delete("/cart")
async def clear_cart(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        await db.cart_items.delete_many({"session_id": session_id})
    return {"message": "Cart cleared"}

# ============ Order Routes ============
@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="No cart found")
    
    cart_items = await db.cart_items.find({"session_id": session_id}, {"_id": 0}).to_list(100)
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    items = []
    total_amount = 0.0
    
    for item in cart_items:
        product = await db.products.find_one({"id": item["product_id"]}, {"_id": 0})
        if product:
            items.append({
                "product_id": product["id"],
                "product_name": product["name"],
                "price": product["price"],
                "quantity": item["quantity"],
                "size": item.get("size")
            })
            total_amount += product["price"] * item["quantity"]
    
    order_id = str(uuid.uuid4())
    transaction_uuid = str(uuid.uuid4())
    
    doc = {
        "id": order_id,
        "customer_name": order_data.customer_name,
        "customer_email": order_data.customer_email,
        "customer_phone": order_data.customer_phone,
        "delivery_address": order_data.delivery_address,
        "items": items,
        "total_amount": total_amount,
        "payment_gateway": order_data.payment_gateway,
        "payment_status": "pending",
        "order_status": "pending",
        "transaction_uuid": transaction_uuid,
        "measurements": order_data.measurements.model_dump() if order_data.measurements else None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.orders.insert_one(doc)
    return Order(**doc)

@api_router.get("/orders", response_model=List[Order])
async def get_orders(request: Request):
    await get_current_user(request)
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return orders

@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order(order_id: str):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@api_router.put("/orders/{order_id}/status")
async def update_order_status(order_id: str, status: dict, request: Request):
    await get_current_user(request)
    result = await db.orders.update_one(
        {"id": order_id},
        {"$set": {"order_status": status.get("order_status")}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Status updated"}

# ============ Payment Routes ============
@api_router.post("/payment/initiate")
async def initiate_payment(order_id: str = Form(...)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if order["payment_gateway"] == "esewa":
        merchant_code = os.environ.get("ESEWA_MERCHANT_CODE")
        total_amount = str(int(order["total_amount"]))
        transaction_uuid = order["transaction_uuid"]
        
        signature = generate_esewa_signature(total_amount, transaction_uuid, merchant_code)
        
        frontend_url = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")[0]
        success_url = f"{frontend_url}/payment/success"
        failure_url = f"{frontend_url}/payment/failure"
        
        form_html = f'''
        <html>
        <body onload="document.esewaForm.submit()">
            <form name="esewaForm" action="{os.environ.get("ESEWA_API_URL")}" method="POST">
                <input type="hidden" name="amount" value="{total_amount}">
                <input type="hidden" name="tax_amount" value="0">
                <input type="hidden" name="product_service_charge" value="0">
                <input type="hidden" name="product_delivery_charge" value="0">
                <input type="hidden" name="total_amount" value="{total_amount}">
                <input type="hidden" name="transaction_uuid" value="{transaction_uuid}">
                <input type="hidden" name="product_code" value="{merchant_code}">
                <input type="hidden" name="signed_field_names" value="total_amount,transaction_uuid,product_code">
                <input type="hidden" name="signature" value="{signature}">
                <input type="hidden" name="success_url" value="{success_url}">
                <input type="hidden" name="failure_url" value="{failure_url}">
            </form>
            <p>Redirecting to eSewa...</p>
        </body>
        </html>
        '''
        return HTMLResponse(content=form_html)
    
    elif order["payment_gateway"] == "khalti":
        khalti_url = os.environ.get("KHALTI_API_URL")
        khalti_secret = os.environ.get("KHALTI_SECRET_KEY")
        frontend_url = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")[0]
        
        payload = {
            "return_url": f"{frontend_url}/payment/success",
            "website_url": frontend_url,
            "amount": int(order["total_amount"] * 100),
            "purchase_order_id": order["id"],
            "purchase_order_name": f"Order #{order['id'][:8]}",
            "customer_info": {
                "name": order["customer_name"],
                "email": order["customer_email"],
                "phone": order["customer_phone"]
            }
        }
        
        try:
            response = requests.post(
                khalti_url,
                headers={
                    "Authorization": f"Key {khalti_secret}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                await db.orders.update_one(
                    {"id": order_id},
                    {"$set": {"pidx": data.get("pidx")}}
                )
                return {"payment_url": data.get("payment_url"), "pidx": data.get("pidx")}
            else:
                raise HTTPException(status_code=500, detail="Khalti payment initiation failed")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    raise HTTPException(status_code=400, detail="Invalid payment gateway")

@api_router.post("/payment/verify")
async def verify_payment(data: dict):
    transaction_uuid = data.get("transaction_uuid")
    pidx = data.get("pidx")
    
    if transaction_uuid:
        order = await db.orders.find_one({"transaction_uuid": transaction_uuid}, {"_id": 0})
    elif pidx:
        order = await db.orders.find_one({"pidx": pidx}, {"_id": 0})
    else:
        raise HTTPException(status_code=400, detail="Missing transaction details")
    
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if order["payment_gateway"] == "khalti" and pidx:
        khalti_verify_url = os.environ.get("KHALTI_VERIFY_URL")
        khalti_secret = os.environ.get("KHALTI_SECRET_KEY")
        
        try:
            response = requests.post(
                khalti_verify_url,
                headers={
                    "Authorization": f"Key {khalti_secret}",
                    "Content-Type": "application/json"
                },
                json={"pidx": pidx},
                timeout=10
            )
            
            if response.status_code == 200:
                payment_data = response.json()
                if payment_data.get("status") == "Completed":
                    await db.orders.update_one(
                        {"id": order["id"]},
                        {"$set": {
                            "payment_status": "completed",
                            "order_status": "confirmed",
                            "payment_verified_at": datetime.now(timezone.utc).isoformat()
                        }}
                    )
                    return {"status": "success", "message": "Payment verified"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    await db.orders.update_one(
        {"id": order["id"]},
        {"$set": {
            "payment_status": "completed",
            "order_status": "confirmed",
            "payment_verified_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    return {"status": "success", "message": "Payment verified"}

# ============ Seed Route for Demo Products ============
@api_router.post("/seed-demo-products")
async def seed_demo_products(request: Request):
    await get_current_user(request)
    
    # Create categories
    categories_data = [
        {"id": "cat-shirting", "name": "Shirting", "description": "Custom tailored shirts"},
        {"id": "cat-suiting", "name": "Suiting", "description": "Bespoke suits and blazers"}
    ]
    
    for cat in categories_data:
        existing = await db.categories.find_one({"id": cat["id"]}, {"_id": 0})
        if not existing:
            await db.categories.insert_one({
                **cat,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
    
    # Create sample products
    products_data = [
        {
            "id": str(uuid.uuid4()),
            "name": "Classic White Dress Shirt",
            "description": "Premium cotton dress shirt with precise tailoring. Perfect for formal occasions and business wear.",
            "price": 3500.0,
            "category_id": "cat-shirting",
            "stock": 50,
            "fabric_type": "Premium Egyptian Cotton",
            "available_sizes": ["S", "M", "L", "XL", "XXL"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Oxford Button-Down Shirt",
            "description": "Classic oxford cloth button-down shirt with custom fit. Versatile and timeless.",
            "price": 3200.0,
            "category_id": "cat-shirting",
            "stock": 40,
            "fabric_type": "Oxford Cotton",
            "available_sizes": ["S", "M", "L", "XL"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Two-Piece Wool Suit",
            "description": "Handcrafted two-piece suit in premium wool. Includes jacket and trousers tailored to perfection.",
            "price": 25000.0,
            "category_id": "cat-suiting",
            "stock": 20,
            "fabric_type": "100% Merino Wool",
            "available_sizes": ["38", "40", "42", "44", "46"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Three-Piece Suit",
            "description": "Complete three-piece suit with jacket, trousers, and vest. The ultimate in formal elegance.",
            "price": 32000.0,
            "category_id": "cat-suiting",
            "stock": 15,
            "fabric_type": "Super 120s Wool",
            "available_sizes": ["38", "40", "42", "44", "46"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Linen Summer Blazer",
            "description": "Lightweight linen blazer perfect for warm weather. Unstructured and comfortable.",
            "price": 18000.0,
            "category_id": "cat-suiting",
            "stock": 25,
            "fabric_type": "Italian Linen",
            "available_sizes": ["S", "M", "L", "XL"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Striped Business Shirt",
            "description": "Professional striped shirt with spread collar. Made from wrinkle-resistant fabric.",
            "price": 3800.0,
            "category_id": "cat-shirting",
            "stock": 35,
            "fabric_type": "Non-Iron Cotton",
            "available_sizes": ["S", "M", "L", "XL", "XXL"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    for product in products_data:
        existing = await db.products.find_one({"name": product["name"]}, {"_id": 0})
        if not existing:
            await db.products.insert_one(product)
    
    return {"message": "Demo products seeded successfully"}

# Include router
app.include_router(api_router)

# CORS
frontend_url = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')[0]
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[frontend_url, "https://tailoring-commerce.preview.emergentagent.com"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()