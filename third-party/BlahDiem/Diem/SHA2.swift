/// Portable SHA-256 and SHA-512 (FIPS 180-4).
public enum SHA2 {
  /// The SHA-256 hash of `message`.
  public static func sha256(_ message: some Collection<UInt8>) -> [UInt8] {
    var h: [UInt32] = [
      0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
      0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ]
    let padded = pad(message, blockSize: 64, lengthBytes: 8)
    var w = [UInt32](repeating: 0, count: 64)
    for block in stride(from: 0, to: padded.count, by: 64) {
      for t in 0..<16 {
        let i = block + t * 4
        w[t] = UInt32(padded[i]) << 24 | UInt32(padded[i + 1]) << 16
          | UInt32(padded[i + 2]) << 8 | UInt32(padded[i + 3])
      }
      for t in 16..<64 {
        let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
      }
      var (a, b, c, d, e, f, g, hh) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
      for t in 0..<64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        let t1 = hh &+ s1 &+ ((e & f) ^ (~e & g)) &+ k256[t] &+ w[t]
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        let t2 = s0 &+ ((a & b) ^ (a & c) ^ (b & c))
        (hh, g, f, e, d, c, b, a) = (g, f, e, d &+ t1, c, b, a, t1 &+ t2)
      }
      for (i, v) in [a, b, c, d, e, f, g, hh].enumerated() { h[i] = h[i] &+ v }
    }
    return h.flatMap { v in (0..<4).reversed().map { UInt8(truncatingIfNeeded: v >> ($0 * 8)) } }
  }

  /// The SHA-512 hash of `message`.
  public static func sha512(_ message: some Collection<UInt8>) -> [UInt8] {
    var h: [UInt64] = [
      0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
      0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]
    let padded = pad(message, blockSize: 128, lengthBytes: 16)
    var w = [UInt64](repeating: 0, count: 80)
    for block in stride(from: 0, to: padded.count, by: 128) {
      for t in 0..<16 {
        var v: UInt64 = 0
        for j in 0..<8 { v = v << 8 | UInt64(padded[block + t * 8 + j]) }
        w[t] = v
      }
      for t in 16..<80 {
        let s0 = rotr(w[t - 15], 1) ^ rotr(w[t - 15], 8) ^ (w[t - 15] >> 7)
        let s1 = rotr(w[t - 2], 19) ^ rotr(w[t - 2], 61) ^ (w[t - 2] >> 6)
        w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
      }
      var (a, b, c, d, e, f, g, hh) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
      for t in 0..<80 {
        let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
        let t1 = hh &+ s1 &+ ((e & f) ^ (~e & g)) &+ k512[t] &+ w[t]
        let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
        let t2 = s0 &+ ((a & b) ^ (a & c) ^ (b & c))
        (hh, g, f, e, d, c, b, a) = (g, f, e, d &+ t1, c, b, a, t1 &+ t2)
      }
      for (i, v) in [a, b, c, d, e, f, g, hh].enumerated() { h[i] = h[i] &+ v }
    }
    return h.flatMap { v in (0..<8).reversed().map { UInt8(truncatingIfNeeded: v >> ($0 * 8)) } }
  }

  private static func pad(_ message: some Collection<UInt8>, blockSize: Int, lengthBytes: Int)
    -> [UInt8]
  {
    var bytes = Array(message)
    let bitLength = UInt64(bytes.count) &* 8
    bytes.append(0x80)
    while (bytes.count + lengthBytes) % blockSize != 0 { bytes.append(0) }
    bytes += [UInt8](repeating: 0, count: lengthBytes - 8)
    bytes += (0..<8).reversed().map { UInt8(truncatingIfNeeded: bitLength >> ($0 * 8)) }
    return bytes
  }

  private static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { x >> n | x << (32 - n) }
  private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { x >> n | x << (64 - n) }

  private static let k256: [UInt32] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
  ]

  private static let k512: [UInt64] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
  ]
}
