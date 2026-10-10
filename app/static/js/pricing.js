// Pricing & Subscription Model Module

function updatePricingCalculator() {
  const brandsSlider = document.getElementById("calc-brands");
  const takedownsSlider = document.getElementById("calc-takedowns");

  if (!brandsSlider || !takedownsSlider) return;

  const brands = parseInt(brandsSlider.value, 10);
  const takedowns = parseInt(takedownsSlider.value, 10);

  document.getElementById("calc-brands-val").innerText = `${brands} ${brands === 1 ? 'Brand' : 'Brands'}`;
  document.getElementById("calc-takedowns-val").innerText = `${takedowns} / month`;

  // Base calculation:
  // $29 base per brand + $15 per takedown ticket
  let total = (brands * 29) + (takedowns * 15);
  
  // Volume discount for > 5 brands
  if (brands >= 5) {
    total = total * 0.85; // 15% discount
  }

  document.getElementById("calc-total-price").innerText = `$${Math.round(total)}`;
}
