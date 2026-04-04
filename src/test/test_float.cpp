// MIT License

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "utility/bit_vector.h"
#include "utility/config.h"

namespace {

struct AbyMetadata {
  std::size_t number_of_server_inputs{0};
  std::size_t number_of_client_inputs{0};
  std::size_t number_of_output_wires{0};
  std::size_t number_of_xor_gates{0};
  std::size_t number_of_and_gates{0};
  std::size_t number_of_mux_gates{0};
  std::size_t number_of_inv_gates{0};
};

std::string TrimCopy(std::string line) {
  const auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  line.erase(line.begin(), std::find_if_not(line.begin(), line.end(), is_space));
  line.erase(std::find_if_not(line.rbegin(), line.rend(), is_space).base(), line.end());
  return line;
}

std::size_t CountWireIds(const std::string& line) {
  std::stringstream ss(line);
  std::string tag;
  ss >> tag;
  std::size_t count = 0;
  long long wire_id = 0;
  while (ss >> wire_id) {
    ++count;
  }
  return count;
}

AbyMetadata ReadAbyMetadata(const std::string& path) {
  std::ifstream stream(path);
  EXPECT_TRUE(stream.is_open()) << path;
  EXPECT_TRUE(stream.good()) << path;

  AbyMetadata metadata;
  std::string line;
  while (std::getline(stream, line)) {
    line = TrimCopy(line);
    if (line.empty() || line.front() == '#') continue;

    const auto has_single_tag =
        (line.size() == 1) || (std::isspace(static_cast<unsigned char>(line[1])) != 0);
    if (!has_single_tag) continue;

    switch (line.front()) {
      case 'S':
        metadata.number_of_server_inputs = CountWireIds(line);
        break;
      case 'C':
        metadata.number_of_client_inputs = CountWireIds(line);
        break;
      case 'O':
        metadata.number_of_output_wires = CountWireIds(line);
        break;
      case 'X':
        ++metadata.number_of_xor_gates;
        break;
      case 'A':
        ++metadata.number_of_and_gates;
        break;
      case 'M':
        ++metadata.number_of_mux_gates;
        break;
      case 'I':
        ++metadata.number_of_inv_gates;
        break;
      default:
        break;
    }
  }

  return metadata;
}

const std::array<const char*, 16> kAbyFloat64Circuits = {
    "circuits/aby/float/fp_ieee_add_64.aby",
    "circuits/aby/float/fp_ieee_div_64.aby",
    "circuits/aby/float/fp_ieee_mult_64.aby",
    "circuits/aby/float/fp_ieee_sqr_64.aby",
    "circuits/aby/float/fp_ieee_sqrt_64.aby",
    "circuits/aby/float/fp_ieee_sub_64.aby",
    "circuits/aby/float/fp_nostatus_add_64.aby",
    "circuits/aby/float/fp_nostatus_cmp_64.aby",
    "circuits/aby/float/fp_nostatus_div_64.aby",
    "circuits/aby/float/fp_nostatus_exp2_64.aby",
    "circuits/aby/float/fp_nostatus_ln_64.aby",
    "circuits/aby/float/fp_nostatus_log2_64.aby",
    "circuits/aby/float/fp_nostatus_mult_64.aby",
    "circuits/aby/float/fp_nostatus_sqr_64.aby",
    "circuits/aby/float/fp_nostatus_sqrt_64.aby",
    "circuits/aby/float/fp_nostatus_sub_64.aby",
};

class AbyFloat64ParserTest : public testing::TestWithParam<const char*> {};

std::vector<std::size_t> GetFloatPartyCounts() {
  if (const char* env = std::getenv("MOTION_FLOAT_PARTY_LIST"); env != nullptr && *env != '\0') {
    std::vector<std::size_t> parsed;
    std::stringstream ss(env);
    std::string token;
    while (std::getline(ss, token, ',')) {
      token = TrimCopy(token);
      if (token.empty()) continue;
      const auto value = std::stoul(token);
      if (value < 2u) {
        throw std::invalid_argument("MOTION_FLOAT_PARTY_LIST values must be >= 2");
      }
      parsed.push_back(value);
    }
    if (!parsed.empty()) return parsed;
  }
  return std::vector<std::size_t>(kNumberOfPartiesList.begin(), kNumberOfPartiesList.end());
}
std::size_t GetFloatRandomTrialCount() {
  constexpr std::size_t kDefaultTrials = 2;
  if (const char* env = std::getenv("MOTION_FLOAT_RANDOM_TRIALS"); env != nullptr && *env != '\0') {
    const auto value = static_cast<std::size_t>(std::stoull(env, nullptr, 10));
    if (value == 0u) {
      throw std::invalid_argument("MOTION_FLOAT_RANDOM_TRIALS must be >= 1");
    }
    return value;
  }
  return kDefaultTrials;
}

std::uint64_t GetFloatRandomSeed() {
  constexpr std::uint64_t kDefaultSeed = 0x4d6f74696f6e464cULL;
  if (const char* env = std::getenv("MOTION_FLOAT_RANDOM_SEED"); env != nullptr && *env != '\0') {
    return std::stoull(env, nullptr, 0);
  }
  return kDefaultSeed;
}

std::mt19937_64 MakeFloatRandomGenerator(std::size_t number_of_parties, std::uint64_t test_id) {
  return std::mt19937_64(GetFloatRandomSeed() ^ (static_cast<std::uint64_t>(number_of_parties) << 32) ^
                         test_id);
}

double SampleUniformDouble(std::mt19937_64& generator, double low, double high) {
  std::uniform_real_distribution<double> distribution(low, high);
  return distribution(generator);
}

double SampleSignedNonZeroDouble(std::mt19937_64& generator, double min_abs, double max_abs) {
  const auto magnitude = SampleUniformDouble(generator, min_abs, max_abs);
  return std::bernoulli_distribution(0.5)(generator) ? magnitude : -magnitude;
}

TEST_P(AbyFloat64ParserTest, FromAbyParsesCircuit) {
  const auto path = std::string(encrypto::motion::kRootDir) + "/" + GetParam();
  const auto metadata = ReadAbyMetadata(path);
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(path);

  const auto expected_number_of_gates = metadata.number_of_xor_gates + metadata.number_of_and_gates +
                                        metadata.number_of_mux_gates + metadata.number_of_inv_gates;
  EXPECT_EQ(algorithm.number_of_gates, expected_number_of_gates);
  EXPECT_EQ(algorithm.gates.size(), expected_number_of_gates);
  EXPECT_EQ(algorithm.number_of_output_wires, metadata.number_of_output_wires);
  EXPECT_EQ(algorithm.output_wire_indices.size(), metadata.number_of_output_wires);
  EXPECT_EQ(algorithm.number_of_wires, algorithm.constant_wires.size());

  for (const auto output_wire : algorithm.output_wire_indices) {
    EXPECT_LT(output_wire, algorithm.number_of_wires);
  }
}

INSTANTIATE_TEST_SUITE_P(Float, AbyFloat64ParserTest, testing::ValuesIn(kAbyFloat64Circuits));

std::vector<encrypto::motion::BitVector<>> EvaluateBinaryAbyCircuitAndOpenToParty0(
    const std::string& relative_path, std::uint64_t a, std::uint64_t b,
    std::size_t number_of_parties = 2) {
  if (number_of_parties < 2) {
    throw std::invalid_argument("Need at least two parties for binary ABY circuit evaluation");
  }

  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;

  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      std::string(encrypto::motion::kRootDir) + "/" + relative_path);

  const auto a_input = encrypto::motion::ToInput(a);
  const auto b_input = encrypto::motion::ToInput(b);

  const std::vector<encrypto::motion::BitVector<>> zeros_a(a_input.size(),
                                                            encrypto::motion::BitVector<>(1, false));
  const std::vector<encrypto::motion::BitVector<>> zeros_b(b_input.size(),
                                                            encrypto::motion::BitVector<>(1, false));

  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<encrypto::motion::ShareWrapper> outputs(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    auto& party = parties.at(party_id);
    auto local_a = (party_id == 0) ? a_input : zeros_a;
    auto local_b = (party_id == 1) ? b_input : zeros_b;

    const encrypto::motion::ShareWrapper share_a(party->In<kProtocol>(std::move(local_a), 0));
    const encrypto::motion::ShareWrapper share_b(party->In<kProtocol>(std::move(local_b), 1));

    const auto concatenated = encrypto::motion::ShareWrapper::Concatenate(
        std::vector<encrypto::motion::ShareWrapper>{share_a, share_b});
    outputs.at(party_id) = concatenated.Evaluate(algorithm).Out(0);
  }

  std::vector<encrypto::motion::BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output]() {
      auto& party = parties.at(party_id);
      party->Run();
      if (party_id == 0) {
        opened_output = outputs.at(party_id).As<std::vector<encrypto::motion::BitVector<>>>();
      }
      party->Reset();
    }));
  }
  for (auto& future : futures) future.get();

  futures.clear();
  futures.reserve(number_of_parties);
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) future.get();

  return opened_output;
}

std::vector<encrypto::motion::BitVector<>> EvaluateUnaryAbyCircuitAndOpenToParty0(
    const std::string& relative_path, std::uint64_t a, std::size_t number_of_parties = 2) {
  if (number_of_parties < 2) {
    throw std::invalid_argument("Need at least two parties for unary ABY circuit evaluation");
  }

  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;

  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      std::string(encrypto::motion::kRootDir) + "/" + relative_path);

  const auto a_input = encrypto::motion::ToInput(a);
  const std::vector<encrypto::motion::BitVector<>> zeros_a(a_input.size(),
                                                            encrypto::motion::BitVector<>(1, false));

  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<encrypto::motion::ShareWrapper> outputs(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    auto& party = parties.at(party_id);
    auto local_a = (party_id == 0) ? a_input : zeros_a;

    const encrypto::motion::ShareWrapper share_a(party->In<kProtocol>(std::move(local_a), 0));
    outputs.at(party_id) = share_a.Evaluate(algorithm).Out(0);
  }

  std::vector<encrypto::motion::BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output]() {
      auto& party = parties.at(party_id);
      party->Run();
      if (party_id == 0) {
        opened_output = outputs.at(party_id).As<std::vector<encrypto::motion::BitVector<>>>();
      }
      party->Reset();
    }));
  }
  for (auto& future : futures) future.get();

  futures.clear();
  futures.reserve(number_of_parties);
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) future.get();

  return opened_output;
}

std::uint64_t EvaluateFloat64BinaryAbyAndOpenToParty0(const std::string& relative_path, double a,
                                                      double b, std::size_t number_of_parties = 2) {
  const auto output = EvaluateBinaryAbyCircuitAndOpenToParty0(
      relative_path, std::bit_cast<std::uint64_t>(a), std::bit_cast<std::uint64_t>(b),
      number_of_parties);
  if (output.size() != 64u) {
    throw std::runtime_error("Unexpected output bit length for float64 circuit");
  }
  return encrypto::motion::ToOutput<std::uint64_t>(output);
}

std::uint64_t EvaluateFloat64UnaryAbyAndOpenToParty0(const std::string& relative_path, double a,
                                                     std::size_t number_of_parties = 2) {
  const auto output =
      EvaluateUnaryAbyCircuitAndOpenToParty0(relative_path, std::bit_cast<std::uint64_t>(a),
                                             number_of_parties);
  if (output.size() != 64u) {
    throw std::runtime_error("Unexpected output bit length for float64 circuit");
  }
  return encrypto::motion::ToOutput<std::uint64_t>(output);
}

bool EvaluateFloat64CmpGtAbyAndOpenToParty0(double a, double b, std::size_t number_of_parties = 2) {
  const auto output = EvaluateBinaryAbyCircuitAndOpenToParty0(
      "circuits/aby/float/fp_nostatus_cmp_64.aby", std::bit_cast<std::uint64_t>(a),
      std::bit_cast<std::uint64_t>(b), number_of_parties);
  if (output.size() != 1u) {
    throw std::runtime_error("Unexpected output bit length for float64 cmp circuit");
  }
  return output[0][0];
}

std::uint64_t EvaluateI2fThenAbyAdd64AndOpenToParty0(std::int64_t int_value, double float_value,
                                                     std::size_t number_of_parties = 2) {
  if (number_of_parties < 2) {
    throw std::invalid_argument("Need at least two parties for i2f+float-add evaluation");
  }

  constexpr auto kBooleanProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticProtocol = encrypto::motion::MpcProtocol::kArithmeticGmw;
  const auto root = std::string(encrypto::motion::kRootDir);

  const auto i2f_algorithm = encrypto::motion::AlgorithmDescription::FromBristolFashion(
      root + "/circuits/float/float_i2f.bristol");
  const auto float_add_algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      root + "/circuits/aby/float/fp_nostatus_add_64.aby");

  const auto float_input = encrypto::motion::ToInput(std::bit_cast<std::uint64_t>(float_value));
  const std::vector<encrypto::motion::BitVector<>> zeros_float(
      float_input.size(), encrypto::motion::BitVector<>(1, false));

  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<encrypto::motion::ShareWrapper> outputs(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    auto& party = parties.at(party_id);
    const std::int64_t local_int_value = (party_id == 0) ? int_value : 0;
    auto local_float = (party_id == 1) ? float_input : zeros_float;

    const encrypto::motion::ShareWrapper int_share_arithmetic(
        party->In<kArithmeticProtocol>(local_int_value, 0));
    const auto int_share_boolean = int_share_arithmetic.Convert<kBooleanProtocol>();
    const encrypto::motion::ShareWrapper float_share(
        party->In<kBooleanProtocol>(std::move(local_float), 1));

    const auto int_as_float = int_share_boolean.Evaluate(i2f_algorithm);
    const auto concatenated = encrypto::motion::ShareWrapper::Concatenate(
        std::vector<encrypto::motion::ShareWrapper>{int_as_float, float_share});
    outputs.at(party_id) = concatenated.Evaluate(float_add_algorithm).Out(0);
  }

  std::vector<encrypto::motion::BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output]() {
      auto& party = parties.at(party_id);
      party->Run();
      if (party_id == 0) {
        opened_output = outputs.at(party_id).As<std::vector<encrypto::motion::BitVector<>>>();
      }
      party->Reset();
    }));
  }
  for (auto& future : futures) future.get();

  futures.clear();
  futures.reserve(number_of_parties);
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) future.get();

  if (opened_output.size() != 64u) {
    throw std::runtime_error("Unexpected output bit length for i2f+float-add circuit");
  }
  return encrypto::motion::ToOutput<std::uint64_t>(opened_output);
}
TEST(FloatMpc64, FromAbyCmp64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xc64001ULL);

    const auto equal_value = SampleUniformDouble(generator, -100.0, 100.0);
    EXPECT_EQ(EvaluateFloat64CmpGtAbyAndOpenToParty0(equal_value, equal_value, number_of_parties), false)
        << "parties=" << number_of_parties << " case=equal a=" << equal_value
        << " b=" << equal_value;

    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -100.0, 100.0);
      const auto b = SampleUniformDouble(generator, -100.0, 100.0);
      const auto expected = a > b;
      EXPECT_EQ(EvaluateFloat64CmpGtAbyAndOpenToParty0(a, b, number_of_parties), expected)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a << " b=" << b;
    }
  }
}

TEST(FloatMpc64, FromAbyAdd64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xa64002ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -100.0, 100.0);
      const auto b = SampleUniformDouble(generator, -100.0, 100.0);
      const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_add_64.aby", a, b, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(a + b);
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a << " b=" << b;
    }
  }
}

TEST(FloatMpc64, FromAbySub64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xb64003ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -100.0, 100.0);
      const auto b = SampleUniformDouble(generator, -100.0, 100.0);
      const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_sub_64.aby", a, b, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(a - b);
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a << " b=" << b;
    }
  }
}

TEST(FloatMpc64, FromAbyMul64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xd64004ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -10.0, 10.0);
      const auto b = SampleUniformDouble(generator, -10.0, 10.0);
      const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_mult_64.aby", a, b, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(a * b);
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a << " b=" << b;
    }
  }
}

TEST(FloatMpc64, DISABLED_FromAbySqr64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xe64005ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -10.0, 10.0);
      const auto result_bits = EvaluateFloat64UnaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_sqr_64.aby", a, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(a * a);
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a;
    }
  }
}

TEST(FloatMpc64, FromAbySqrt64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf64006ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, 0.0, 100.0);
      const auto result_bits = EvaluateFloat64UnaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_sqrt_64.aby", a, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(std::sqrt(a));
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a;
    }
  }
}

TEST(FloatMpc64, FromBristolI2fThenFromAbyAdd64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0x164007ULL);
    std::uniform_int_distribution<std::int64_t> int_distribution(-1000000, 1000000);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto int_value = int_distribution(generator);
      const auto float_value = SampleUniformDouble(generator, -1000.0, 1000.0);
      const auto result_bits =
          EvaluateI2fThenAbyAdd64AndOpenToParty0(int_value, float_value, number_of_parties);
      const auto expected_bits =
          std::bit_cast<std::uint64_t>(static_cast<double>(int_value) + float_value);
      EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties
                                            << " trial=" << trial << " int=" << int_value
                                            << " float=" << float_value;
    }
  }
}

TEST(FloatMpc64, FromAbyDiv64_2_3_4_5_10_parties) {
  const auto trial_count = GetFloatRandomTrialCount();

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    auto generator = MakeFloatRandomGenerator(number_of_parties, 0x264008ULL);
    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto a = SampleUniformDouble(generator, -100.0, 100.0);
      const auto b = SampleSignedNonZeroDouble(generator, 0.5, 10.0);
      const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
          "circuits/aby/float/fp_nostatus_div_64.aby", a, b, number_of_parties);
      const auto expected_bits = std::bit_cast<std::uint64_t>(a / b);
      EXPECT_EQ(result_bits, expected_bits)
          << "parties=" << number_of_parties << " trial=" << trial << " a=" << a << " b=" << b;
    }
  }
}

}  // namespace

