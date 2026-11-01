const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret, defineString } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");
const { ethers } = require("ethers");
admin.initializeApp();
const db = admin.firestore();

// Settings (set with: firebase functions:secrets:set NAME / .env file for strings)
const RZP_KEY_ID = defineString("RZP_KEY_ID");
const RZP_SECRET = defineSecret("RZP_SECRET");
const RZP_WEBHOOK_SECRET = defineSecret("RZP_WEBHOOK_SECRET");
const TREASURY_KEY = defineSecret("TREASURY_KEY"); // private key of the treasury wallet that holds META + gas
const RPC = defineString("RPC_URL");
const TOKEN = defineString("TOKEN_ADDRESS");
const TREASURY = defineString("TREASURY_ADDRESS");

const DECIMALS = 8n, PRICE_PAISE = 30n;           // ₹0.30 per META
const MIN_INR = 100, MAX_INR = 10000;               // per order limits
const ABI = ["function transfer(address,uint256) returns (bool)",
             "event Transfer(address indexed from,address indexed to,uint256 value)"];
const opts = { secrets: [RZP_SECRET, RZP_WEBHOOK_SECRET, TREASURY_KEY], cors: true, region: "asia-south1" };

// 1) Buy: create a Razorpay order for the amount in rupees
exports.createOrder = onRequest(opts, async (req, res) => {
  try {
    const inr = Number(req.body.inr), address = ethers.getAddress(String(req.body.address));
    if (!(inr >= MIN_INR && inr <= MAX_INR)) return res.status(400).json({ error: `Amount must be ₹${MIN_INR} to ₹${MAX_INR}` });
    const paise = BigInt(Math.round(inr * 100));
    const units = (paise * 10n ** DECIMALS) / PRICE_PAISE;   // META in smallest units
    const r = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json",
        Authorization: "Basic " + Buffer.from(`${RZP_KEY_ID.value()}:${RZP_SECRET.value()}`).toString("base64") },
      body: JSON.stringify({ amount: Number(paise), currency: "INR" }) });
    const order = await r.json();
    if (!order.id) return res.status(502).json({ error: "Payment provider error" });
    await db.collection("orders").doc(order.id).set({ address, paise: Number(paise), units: units.toString(), status: "created", at: Date.now() });
    res.json({ orderId: order.id, keyId: RZP_KEY_ID.value(), amount: Number(paise) });
  } catch (e) { res.status(400).json({ error: "Invalid request" }); }
});

// 2) Razorpay webhook: after verified payment, send META from the treasury (once only)
exports.razorpayWebhook = onRequest(opts, async (req, res) => {
  const sig = req.get("X-Razorpay-Signature") || "";
  const want = crypto.createHmac("sha256", RZP_WEBHOOK_SECRET.value()).update(req.rawBody).digest("hex");
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return res.status(401).end();
  if (req.body.event !== "payment.captured") return res.status(200).end();
  const p = req.body.payload.payment.entity, ref = db.collection("orders").doc(p.order_id);
  const order = await db.runTransaction(async t => {
    const s = await t.get(ref);
    if (!s.exists || s.data().status !== "created" || s.data().paise !== p.amount) return null;
    t.update(ref, { status: "paying", paymentId: p.id }); return s.data();
  });
  if (!order) return res.status(200).end();            // unknown, wrong amount, or already handled
  try {
    const w = new ethers.Wallet(TREASURY_KEY.value(), new ethers.JsonRpcProvider(RPC.value()));
    const tx = await new ethers.Contract(TOKEN.value(), ABI, w).transfer(order.address, BigInt(order.units));
    await ref.update({ status: "completed", txHash: tx.hash });
  } catch (e) { await ref.update({ status: "paid_needs_review", error: String(e.message).slice(0, 200) }); }
  res.status(200).end();
});

// 3) Withdraw: user sends META to the treasury, then proves it with a signed request.
//    The payout (UPI/bank) is reviewed and paid by you; status moves pending_review -> paid.
exports.requestWithdraw = onRequest(opts, async (req, res) => {
  try {
    const { txHash, upi, signature } = req.body;
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash) || !/^[\w.\-]{2,}@[\w]{2,}$/.test(upi)) return res.status(400).json({ error: "Invalid details" });
    const signer = ethers.verifyMessage(`META withdraw ${txHash} to ${upi}`, signature);
    const rc = await new ethers.JsonRpcProvider(RPC.value()).getTransactionReceipt(txHash);
    if (!rc || rc.status !== 1) return res.status(400).json({ error: "Transaction not confirmed yet" });
    const iface = new ethers.Interface(ABI);
    let units = 0n;
    for (const l of rc.logs) {
      if (l.address.toLowerCase() !== TOKEN.value().toLowerCase()) continue;
      const ev = iface.parseLog(l);
      if (ev && ev.name === "Transfer" && ev.args.from === signer && ev.args.to.toLowerCase() === TREASURY.value().toLowerCase()) units += ev.args.value;
    }
    if (units === 0n) return res.status(400).json({ error: "No META transfer from your wallet to the treasury found" });
    const inrPaise = (units * PRICE_PAISE) / 10n ** DECIMALS;
    const ref = db.collection("withdrawals").doc(txHash);   // txHash as id => cannot be claimed twice
    try { await ref.create({ signer, upi, units: units.toString(), inr: Number(inrPaise) / 100, status: "pending_review", at: Date.now() }); }
    catch (e) { return res.status(409).json({ error: "Already submitted" }); }
    res.json({ status: "pending_review", inr: Number(inrPaise) / 100 });
  } catch (e) { res.status(400).json({ error: "Invalid request" }); }
});

// 4) Admin report (read-only). Send header: Authorization: Bearer <ADMIN_TOKEN>
const ADMIN_TOKEN = defineSecret("ADMIN_TOKEN");
exports.adminReport = onRequest({ secrets: [ADMIN_TOKEN], cors: false, region: "asia-south1" }, async (req, res) => {
  const got = (req.get("Authorization") || "").replace("Bearer ", ""), want = ADMIN_TOKEN.value();
  if (got.length !== want.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want))) return res.status(401).end();
  const snap = await db.collection("orders").orderBy("at", "desc").limit(1000).get();
  res.json({ orders: snap.docs.map(d => ({ id: d.id, address: d.data().address, paise: d.data().paise, units: d.data().units, status: d.data().status, at: d.data().at })) });
});
