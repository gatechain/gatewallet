const { Scalar } = require("ffjavascript");
const circomlib = require("circomlib");
const { ethers } = require("ethers");

function formatAmount(str, dis) {
  return ethers.utils.parseUnits(str.toString(), dis || 20).toString();
}
// spot
function buildSpotOrder(tx) {
  let res = Scalar.e(0);
  res = Scalar.add(res, tx.user_id || 0);
  res = Scalar.add(res, Scalar.shl(tx.token_id || 0, 48));
  res = Scalar.add(res, Scalar.shl(tx.money_id || 0, 64));
  res = Scalar.add(res, Scalar.shl(tx.side || 0, 80));
  res = Scalar.add(
    res,
    Scalar.shl(formatAmount(tx.amount) || formatAmount(0), 81)
  );
  res = Scalar.add(
    res,
    Scalar.shl(formatAmount(tx.price) || formatAmount(0), 209)
  );
  const h = circomlib.poseidon([res]);
  return h;
}

function buildSpotCancelOrder(tx) {
  let res = Scalar.e(0);
  res = Scalar.add(res, tx.user_id || 0);
  res = Scalar.add(res, Scalar.shl(tx.order_id || 0, 48));
  const h = circomlib.poseidon([res]);
  return h;
}
function buildSpotWithdraw(tx) {
  let res = Scalar.e(0);
  res = Scalar.add(res, tx.user_id || 0);
  res = Scalar.add(res, Scalar.shl(tx.business_type || 0, 48));
  res = Scalar.add(res, Scalar.shl(tx.token_id || 0, 64));
  res = Scalar.add(
    res,
    Scalar.shl(formatAmount(tx.amount) || formatAmount(0), 80)
  );
  const h = circomlib.poseidon([res]);
  return h;
}
module.exports = {
  buildSpotOrder,
  buildSpotCancelOrder,
  buildSpotWithdraw,
};
