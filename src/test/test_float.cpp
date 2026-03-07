// MIT License

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
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
      party->Finish();
    }));
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
      party->Finish();
    }));
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

  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;
  const auto root = std::string(encrypto::motion::kRootDir);

  const auto i2f_algorithm = encrypto::motion::AlgorithmDescription::FromBristolFashion(
      root + "/circuits/float/float_i2f.bristol");
  const auto float_add_algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      root + "/circuits/aby/float/fp_nostatus_add_64.aby");

  const auto int_input = encrypto::motion::ToInput(static_cast<std::uint64_t>(int_value));
  const auto float_input = encrypto::motion::ToInput(std::bit_cast<std::uint64_t>(float_value));
  const std::vector<encrypto::motion::BitVector<>> zeros_int(int_input.size(),
                                                              encrypto::motion::BitVector<>(1, false));
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
    auto local_int = (party_id == 0) ? int_input : zeros_int;
    auto local_float = (party_id == 1) ? float_input : zeros_float;

    const encrypto::motion::ShareWrapper int_share(party->In<kProtocol>(std::move(local_int), 0));
    const encrypto::motion::ShareWrapper float_share(
        party->In<kProtocol>(std::move(local_float), 1));

    const auto int_as_float = int_share.Evaluate(i2f_algorithm);
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
      party->Finish();
    }));
  }
  for (auto& future : futures) future.get();

  if (opened_output.size() != 64u) {
    throw std::runtime_error("Unexpected output bit length for i2f+float-add circuit");
  }
  return encrypto::motion::ToOutput<std::uint64_t>(opened_output);
}

TEST(FloatMpc64, FromAbyCmp64_2_3_4_5_10_parties) {
  const std::vector<std::tuple<double, double, bool>> cases = {
      {2.0, 1.0, true},
      {1.0, 2.0, false},
      {-1.0, -2.0, true},
      {0.0, 0.0, false},
  };

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    for (std::size_t i = 0; i < cases.size(); ++i) {
      const auto [a, b, expected] = cases[i];
      EXPECT_EQ(EvaluateFloat64CmpGtAbyAndOpenToParty0(a, b, number_of_parties), expected)
          << "parties=" << number_of_parties << " case #" << i << " a=" << a << " b=" << b;
    }
  }
}

TEST(FloatMpc64, FromAbyAdd64_2_3_4_5_10_parties) {
  const double a = 5.5;
  const double b = 1.25;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_add_64.aby", a, b, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(a + b);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, FromAbySub64_2_3_4_5_10_parties) {
  const double a = 5.5;
  const double b = 2.25;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_sub_64.aby", a, b, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(a - b);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, FromAbyMul64_2_3_4_5_10_parties) {
  const double a = 1.5;
  const double b = 2.0;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_mult_64.aby", a, b, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(a * b);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, DISABLED_FromAbySqr64_2_3_4_5_10_parties) {
  const double a = 1.5;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64UnaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_sqr_64.aby", a, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(a * a);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, FromAbySqrt64_2_3_4_5_10_parties) {
  const double a = 4.0;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64UnaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_sqrt_64.aby", a, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(2.0);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, FromBristolI2fThenFromAbyAdd64_2_3_4_5_10_parties) {
  const std::int64_t int_value = 3;
  const double float_value = 2.25;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits =
        EvaluateI2fThenAbyAdd64AndOpenToParty0(int_value, float_value, number_of_parties);
    const auto expected_bits =
        std::bit_cast<std::uint64_t>(static_cast<double>(int_value) + float_value);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

TEST(FloatMpc64, FromAbyDiv64_2_3_4_5_10_parties) {
  const double a = 7.5;
  const double b = 2.5;

  for (const auto number_of_parties : GetFloatPartyCounts()) {
    const auto result_bits = EvaluateFloat64BinaryAbyAndOpenToParty0(
        "circuits/aby/float/fp_nostatus_div_64.aby", a, b, number_of_parties);
    const auto expected_bits = std::bit_cast<std::uint64_t>(a / b);
    EXPECT_EQ(result_bits, expected_bits) << "parties=" << number_of_parties;
  }
}

}  // namespace





