// MIT License

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "communication/transport.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "test_constants.h"
#include "utility/bit_vector.h"
#include "utility/config.h"

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

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

struct BristolMetadata {
  const char* relative_path{nullptr};
  std::size_t number_of_gates{0};
  std::size_t number_of_wires{0};
  std::size_t number_of_input_wires_parent_a{0};
  std::size_t number_of_input_wires_parent_b{0};
  std::size_t number_of_output_wires{0};
};

const std::array<BristolMetadata, 4> kBristolFloat32Circuits = {{
    {"circuits/float/float_add32_size.bristol", 363, 379, 8, 8, 32},
    {"circuits/float/float_add32_depth.bristol", 360, 376, 8, 8, 32},
    {"circuits/float/float_mul32_size.bristol", 1689, 1705, 8, 8, 32},
    {"circuits/float/float_mul32_depth.bristol", 2166, 2182, 8, 8, 32},
}};

class AbyFloat64ParserTest : public testing::TestWithParam<const char*> {};
class BristolFloat32ParserTest : public testing::TestWithParam<BristolMetadata> {};

using encrypto::motion::AccumulatedCommunicationStatistics;
using encrypto::motion::AccumulatedRunTimeStatistics;
using encrypto::motion::BitVector;
using encrypto::motion::Party;
using encrypto::motion::PrintStatistics;

struct FloatLifecycleBenchmarkResult {
  double total_ms{0.0};
  double wall_total_ms{0.0};
  double party_create_ms{0.0};
  double configure_ms{0.0};
  double round_run_ms{0.0};
  double reset_ms{0.0};
  double finish_ms{0.0};
  double cleanup_finish_ms{0.0};
  AccumulatedRunTimeStatistics run_time_statistics;
  AccumulatedCommunicationStatistics communication_statistics;
};

struct FloatInputPassLifecycleBenchmarkResult {
  double total_ms{0.0};
  double wall_total_ms{0.0};
  double party_create_ms{0.0};
  double configure_ms{0.0};
  double input_run_ms{0.0};
  double input_reset_ms{0.0};
  double input_finish_ms{0.0};
  double add_run_ms{0.0};
  double add_reset_ms{0.0};
  double add_finish_ms{0.0};
  double cleanup_finish_ms{0.0};
  AccumulatedRunTimeStatistics run_time_statistics;
  AccumulatedCommunicationStatistics communication_statistics;
};

struct FloatTcpProcessLifecycleBenchmarkResult {
  double total_ms{0.0};
  double wall_total_ms{0.0};
  double party_create_ms{0.0};
  double configure_ms{0.0};
  double input_run_ms{0.0};
  double input_reset_ms{0.0};
  double add_run_ms{0.0};
  double add_reset_ms{0.0};
  double finish_ms{0.0};
  double messages_sent{0.0};
  double messages_received{0.0};
  double bytes_sent{0.0};
  double bytes_received{0.0};
  double tcp_send_time_ms{0.0};
  double tcp_receive_time_ms{0.0};
  double tcp_receive_wait_time_ms{0.0};
  double tcp_receive_message_size_time_ms{0.0};
  double tcp_receive_payload_time_ms{0.0};
};

struct FloatLifecycleOperation {
  std::string name;
  std::string relative_path;
};

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

std::vector<std::size_t> GetFloatLifecyclePartyCounts() {
  if (const char* env = std::getenv("MOTION_FLOAT_LIFECYCLE_PARTY_LIST");
      env != nullptr && *env != '\0') {
    std::vector<std::size_t> parsed;
    std::stringstream ss(env);
    std::string token;
    while (std::getline(ss, token, ',')) {
      token = TrimCopy(token);
      if (token.empty()) continue;
      const auto value = std::stoul(token);
      if (value < 2u) {
        throw std::invalid_argument("MOTION_FLOAT_LIFECYCLE_PARTY_LIST values must be >= 2");
      }
      parsed.push_back(value);
    }
    if (!parsed.empty()) return parsed;
  }
  return {2u};
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

std::size_t GetEnvSizeT(const char* name, std::size_t default_value) {
  if (const char* env = std::getenv(name); env != nullptr && *env != '\0') {
    const auto value = static_cast<std::size_t>(std::stoull(env, nullptr, 10));
    if (value == 0u) {
      throw std::invalid_argument(std::string(name) + " must be >= 1");
    }
    return value;
  }
  return default_value;
}

std::size_t GetEnvSizeTAllowZero(const char* name, std::size_t default_value) {
  if (const char* env = std::getenv(name); env != nullptr && *env != '\0') {
    return static_cast<std::size_t>(std::stoull(env, nullptr, 10));
  }
  return default_value;
}

FloatLifecycleOperation GetFloatLifecycleOperation() {
  std::string op = "add";
  if (const char* env = std::getenv("MOTION_FLOAT_LIFECYCLE_OP");
      env != nullptr && *env != '\0') {
    op = env;
  }

  if (op == "add") {
    return {"add", "circuits/aby/float/fp_nostatus_add_64.aby"};
  }
  if (op == "sub") {
    return {"sub", "circuits/aby/float/fp_nostatus_sub_64.aby"};
  }
  if (op == "mul") {
    return {"mul", "circuits/aby/float/fp_nostatus_mult_64.aby"};
  }
  if (op == "div") {
    return {"div", "circuits/aby/float/fp_nostatus_div_64.aby"};
  }
  throw std::invalid_argument("MOTION_FLOAT_LIFECYCLE_OP must be one of add, sub, mul, div");
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

double ToMilliseconds(std::chrono::steady_clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

double Median(std::vector<double> values) {
  if (values.empty()) {
    return 0.0;
  }

  std::sort(values.begin(), values.end());
  const auto middle = values.size() / 2;
  if ((values.size() % 2) == 1) {
    return values.at(middle);
  }
  return 0.5 * (values.at(middle - 1) + values.at(middle));
}

template <typename Result>
std::vector<double> CollectField(const std::vector<Result>& results, double Result::*field) {
  std::vector<double> values;
  values.reserve(results.size());
  for (const auto& result : results) {
    values.push_back(result.*field);
  }
  return values;
}

double ComputeFloatLifecycleExpected(const std::string& op, double a, double b) {
  if (op == "add") return a + b;
  if (op == "sub") return a - b;
  if (op == "mul") return a * b;
  if (op == "div") return a / b;
  throw std::invalid_argument("Unsupported float lifecycle operation");
}

std::pair<double, double> MakeFloatLifecycleInputs(std::mt19937_64& generator,
                                                   const std::string& op) {
  if (op == "mul") {
    return {SampleUniformDouble(generator, -10.0, 10.0),
            SampleUniformDouble(generator, -10.0, 10.0)};
  }
  if (op == "div") {
    return {SampleUniformDouble(generator, -100.0, 100.0),
            SampleSignedNonZeroDouble(generator, 0.5, 10.0)};
  }
  return {SampleUniformDouble(generator, -100.0, 100.0),
          SampleUniformDouble(generator, -100.0, 100.0)};
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

TEST_P(BristolFloat32ParserTest, FromBristolParsesCircuit) {
  const auto metadata = GetParam();
  const auto path = std::string(encrypto::motion::kRootDir) + "/" + metadata.relative_path;
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromBristol(path);

  EXPECT_EQ(algorithm.number_of_gates, metadata.number_of_gates);
  EXPECT_EQ(algorithm.gates.size(), metadata.number_of_gates);
  EXPECT_EQ(algorithm.number_of_wires, metadata.number_of_wires);
  EXPECT_EQ(algorithm.number_of_input_wires_parent_a, metadata.number_of_input_wires_parent_a);
  ASSERT_TRUE(algorithm.number_of_input_wires_parent_b.has_value());
  EXPECT_EQ(*algorithm.number_of_input_wires_parent_b, metadata.number_of_input_wires_parent_b);
  EXPECT_EQ(algorithm.number_of_output_wires, metadata.number_of_output_wires);
  EXPECT_EQ(algorithm.output_wire_indices.size(), metadata.number_of_output_wires);
  EXPECT_EQ(algorithm.constant_wires.size(), metadata.number_of_wires);

  const auto has_or_gate =
      std::any_of(algorithm.gates.begin(), algorithm.gates.end(), [](const auto& gate) {
        return gate.type == encrypto::motion::PrimitiveOperationType::kOr;
      });
  EXPECT_TRUE(has_or_gate);
}

INSTANTIATE_TEST_SUITE_P(Float, BristolFloat32ParserTest,
                         testing::ValuesIn(kBristolFloat32Circuits));

std::uint32_t EvaluateBristolU8BinaryInClear(const encrypto::motion::AlgorithmDescription& algorithm,
                                             std::uint8_t a, std::uint8_t b) {
  const auto expected_inputs =
      algorithm.number_of_input_wires_parent_a + algorithm.number_of_input_wires_parent_b.value_or(0u);
  if (expected_inputs != 16u) {
    throw std::runtime_error("Expected a Bristol circuit with 16 input wires");
  }
  if (algorithm.number_of_output_wires != 32u) {
    throw std::runtime_error("Expected a Bristol circuit with 32 output wires");
  }

  std::vector<std::optional<bool>> wire_values(algorithm.number_of_wires, std::nullopt);
  for (std::size_t i = 0; i < 8u; ++i) {
    wire_values.at(i) = ((a >> i) & 0x1u) != 0u;
  }
  for (std::size_t i = 0; i < 8u; ++i) {
    wire_values.at(8u + i) = ((b >> i) & 0x1u) != 0u;
  }
  if (!algorithm.constant_wires.empty()) {
    for (std::size_t i = 0; i < std::min(algorithm.constant_wires.size(), wire_values.size()); ++i) {
      if (wire_values.at(i).has_value()) continue;
      if (!algorithm.constant_wires.at(i).has_value()) continue;
      wire_values.at(i) = algorithm.constant_wires.at(i);
    }
  }

  const auto read_wire = [&](std::size_t index) {
    if (index >= wire_values.size() || !wire_values.at(index).has_value()) {
      throw std::runtime_error("Wire referenced before assignment during clear Bristol evaluation");
    }
    return *wire_values.at(index);
  };

  for (const auto& gate : algorithm.gates) {
    bool output_value = false;
    switch (gate.type) {
      case encrypto::motion::PrimitiveOperationType::kXor:
        output_value = read_wire(gate.parent_a) ^ read_wire(*gate.parent_b);
        break;
      case encrypto::motion::PrimitiveOperationType::kAnd:
        output_value = read_wire(gate.parent_a) && read_wire(*gate.parent_b);
        break;
      case encrypto::motion::PrimitiveOperationType::kOr:
        output_value = read_wire(gate.parent_a) || read_wire(*gate.parent_b);
        break;
      case encrypto::motion::PrimitiveOperationType::kInv:
        output_value = !read_wire(gate.parent_a);
        break;
      case encrypto::motion::PrimitiveOperationType::kMux:
        output_value = read_wire(*gate.selection_bit) ? read_wire(*gate.parent_b) : read_wire(gate.parent_a);
        break;
      default:
        throw std::runtime_error("Unsupported gate type in clear Bristol evaluator");
    }
    wire_values.at(gate.output_wire) = output_value;
  }

  std::vector<std::size_t> output_indices;
  if (!algorithm.output_wire_indices.empty()) {
    output_indices = algorithm.output_wire_indices;
  } else {
    output_indices.reserve(algorithm.number_of_output_wires);
    const auto start = algorithm.number_of_wires - algorithm.number_of_output_wires;
    for (std::size_t i = 0; i < algorithm.number_of_output_wires; ++i) {
      output_indices.push_back(start + i);
    }
  }
  if (output_indices.size() != 32u) {
    throw std::runtime_error("Expected exactly 32 output indices");
  }

  std::uint32_t output = 0u;
  for (std::size_t i = 0; i < output_indices.size(); ++i) {
    if (read_wire(output_indices.at(i))) {
      output |= (std::uint32_t{1} << i);
    }
  }
  return output;
}

TEST(FloatBristol32, AddSizeDepthEquivalentInClearExhaustive) {
  const auto root = std::string(encrypto::motion::kRootDir);
  const auto add_size = encrypto::motion::AlgorithmDescription::FromBristol(
      root + "/circuits/float/float_add32_size.bristol");
  const auto add_depth = encrypto::motion::AlgorithmDescription::FromBristol(
      root + "/circuits/float/float_add32_depth.bristol");

  for (std::uint32_t a = 0u; a < 256u; ++a) {
    for (std::uint32_t b = 0u; b < 256u; ++b) {
      const auto y_size = EvaluateBristolU8BinaryInClear(add_size, static_cast<std::uint8_t>(a),
                                                         static_cast<std::uint8_t>(b));
      const auto y_depth = EvaluateBristolU8BinaryInClear(add_depth, static_cast<std::uint8_t>(a),
                                                          static_cast<std::uint8_t>(b));
      EXPECT_EQ(y_size, y_depth) << "a=" << a << " b=" << b;
    }
  }
}

TEST(FloatBristol32, MulSizeDepthEquivalentInClearExhaustive) {
  const auto root = std::string(encrypto::motion::kRootDir);
  const auto mul_size = encrypto::motion::AlgorithmDescription::FromBristol(
      root + "/circuits/float/float_mul32_size.bristol");
  const auto mul_depth = encrypto::motion::AlgorithmDescription::FromBristol(
      root + "/circuits/float/float_mul32_depth.bristol");

  for (std::uint32_t a = 0u; a < 256u; ++a) {
    for (std::uint32_t b = 0u; b < 256u; ++b) {
      const auto y_size = EvaluateBristolU8BinaryInClear(mul_size, static_cast<std::uint8_t>(a),
                                                         static_cast<std::uint8_t>(b));
      const auto y_depth = EvaluateBristolU8BinaryInClear(mul_depth, static_cast<std::uint8_t>(a),
                                                          static_cast<std::uint8_t>(b));
      EXPECT_EQ(y_size, y_depth) << "a=" << a << " b=" << b;
    }
  }
}

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

void ResetAllFloatLifecycleParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Reset(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void FinishAllFloatLifecycleParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void CollectFloatLifecycleRunTimeStatistics(
    const std::vector<std::unique_ptr<Party>>& parties,
    AccumulatedRunTimeStatistics& run_time_statistics,
    AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr) {
  for (const auto& party : parties) {
    const auto& runs = party->GetBackend()->GetRunTimeStatistics();
    ASSERT_FALSE(runs.empty());
    run_time_statistics.Add(runs.back());
    if (accumulated_run_time_statistics != nullptr) {
      accumulated_run_time_statistics->Add(runs.back());
    }
  }
}

void AddFloatLifecycleTransportStatistics(
    encrypto::motion::communication::TransportStatistics& target,
    const encrypto::motion::communication::TransportStatistics& source) {
  target.number_of_messages_sent += source.number_of_messages_sent;
  target.number_of_messages_received += source.number_of_messages_received;
  target.number_of_bytes_sent += source.number_of_bytes_sent;
  target.number_of_bytes_received += source.number_of_bytes_received;
}

void AccumulateFloatLifecycleRoundTransportStatistics(
    std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>&
        total_transport_statistics,
    const std::vector<std::unique_ptr<Party>>& parties) {
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    const auto round_statistics =
        parties.at(party_id)->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    if (total_transport_statistics.at(party_id).empty()) {
      total_transport_statistics.at(party_id) = round_statistics;
      continue;
    }
    ASSERT_EQ(total_transport_statistics.at(party_id).size(), round_statistics.size());
    for (std::size_t i = 0; i < round_statistics.size(); ++i) {
      AddFloatLifecycleTransportStatistics(total_transport_statistics.at(party_id).at(i),
                                           round_statistics.at(i));
    }
  }
}

void CollectFloatLifecycleCommunicationStatistics(
    const std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>&
        transport_statistics,
    AccumulatedCommunicationStatistics& local_statistics,
    AccumulatedCommunicationStatistics* accumulated_statistics = nullptr) {
  for (const auto& statistics_by_peer : transport_statistics) {
    local_statistics.Add(statistics_by_peer);
    if (accumulated_statistics != nullptr) {
      accumulated_statistics->Add(statistics_by_peer);
    }
  }
}

void RunAllFloatLifecycleParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Run(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

std::vector<encrypto::motion::ShareWrapper> RunFloatLifecycleInputPassAndKeepShares(
    std::vector<std::unique_ptr<Party>>& parties, std::uint64_t input, std::size_t input_owner) {
  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;

  const auto input_bits = encrypto::motion::ToInput(input);
  const std::vector<BitVector<>> zero_bits(input_bits.size(), BitVector<>(1, false));

  std::vector<encrypto::motion::ShareWrapper> shares(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    auto local_input = (party_id == input_owner) ? input_bits : zero_bits;
    shares.at(party_id) =
        encrypto::motion::ShareWrapper(parties.at(party_id)->In<kProtocol>(
            std::move(local_input), input_owner));
  }

  RunAllFloatLifecycleParties(parties);
  return shares;
}

void RunFloatLifecycleInputPass(std::vector<std::unique_ptr<Party>>& parties, std::uint64_t input,
                                std::size_t input_owner) {
  (void)RunFloatLifecycleInputPassAndKeepShares(parties, input, input_owner);
}

void RunFloatLifecycleAbyRound(std::vector<std::unique_ptr<Party>>& parties,
                               const encrypto::motion::AlgorithmDescription& algorithm,
                               const std::string& op, double a, double b) {
  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;

  const auto a_input = encrypto::motion::ToInput(std::bit_cast<std::uint64_t>(a));
  const auto b_input = encrypto::motion::ToInput(std::bit_cast<std::uint64_t>(b));
  const std::vector<BitVector<>> zeros_a(a_input.size(), BitVector<>(1, false));
  const std::vector<BitVector<>> zeros_b(b_input.size(), BitVector<>(1, false));

  std::vector<encrypto::motion::ShareWrapper> outputs(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    auto& party = parties.at(party_id);
    auto local_a = (party_id == 0) ? a_input : zeros_a;
    auto local_b = (party_id == 1) ? b_input : zeros_b;

    const encrypto::motion::ShareWrapper share_a(party->In<kProtocol>(std::move(local_a), 0));
    const encrypto::motion::ShareWrapper share_b(party->In<kProtocol>(std::move(local_b), 1));
    const auto concatenated = encrypto::motion::ShareWrapper::Concatenate(
        std::vector<encrypto::motion::ShareWrapper>{share_a, share_b});
    outputs.at(party_id) = concatenated.Evaluate(algorithm).Out(0);
  }

  std::vector<BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    futures.emplace_back(
        std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output] {
          auto& party = parties.at(party_id);
          party->Run();
          if (party_id == 0) {
            opened_output = outputs.at(party_id).As<std::vector<BitVector<>>>();
          }
        }));
  }
  for (auto& future : futures) {
    future.get();
  }

  ASSERT_EQ(opened_output.size(), 64u);
  const auto result_bits = encrypto::motion::ToOutput<std::uint64_t>(opened_output);
  const auto expected_bits =
      std::bit_cast<std::uint64_t>(ComputeFloatLifecycleExpected(op, a, b));
  EXPECT_EQ(result_bits, expected_bits) << "op=" << op << " a=" << a << " b=" << b;
}

void RunFloatLifecycleAbyRoundWithShares(
    std::vector<std::unique_ptr<Party>>& parties,
    const encrypto::motion::AlgorithmDescription& algorithm, const std::string& op, double a,
    double b, const std::vector<encrypto::motion::ShareWrapper>& share_a_by_party,
    const std::vector<encrypto::motion::ShareWrapper>& share_b_by_party) {
  ASSERT_EQ(share_a_by_party.size(), parties.size());
  ASSERT_EQ(share_b_by_party.size(), parties.size());

  std::vector<encrypto::motion::ShareWrapper> outputs(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    const auto concatenated = encrypto::motion::ShareWrapper::Concatenate(
        std::vector<encrypto::motion::ShareWrapper>{share_a_by_party.at(party_id),
                                                    share_b_by_party.at(party_id)});
    outputs.at(party_id) = concatenated.Evaluate(algorithm).Out(0);
  }

  std::vector<BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    futures.emplace_back(
        std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output] {
          auto& party = parties.at(party_id);
          party->Run();
          if (party_id == 0) {
            opened_output = outputs.at(party_id).As<std::vector<BitVector<>>>();
          }
        }));
  }
  for (auto& future : futures) {
    future.get();
  }

  ASSERT_EQ(opened_output.size(), 64u);
  const auto result_bits = encrypto::motion::ToOutput<std::uint64_t>(opened_output);
  const auto expected_bits =
      std::bit_cast<std::uint64_t>(ComputeFloatLifecycleExpected(op, a, b));
  EXPECT_EQ(result_bits, expected_bits) << "op=" << op << " a=" << a << " b=" << b
                                        << " using shares carried across Reset";
}

FloatLifecycleBenchmarkResult BenchmarkFloatLifecycleUsingReset(
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t number_of_parties,
    std::size_t rounds, AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  FloatLifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();
  auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf10a7ULL);

  auto stage_start = std::chrono::steady_clock::now();
  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  stage_start = std::chrono::steady_clock::now();
  ConfigurePartiesForPerformance(parties);
  result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  for (std::size_t round = 0; round < rounds; ++round) {
    const auto [a, b] = MakeFloatLifecycleInputs(generator, operation.name);
    stage_start = std::chrono::steady_clock::now();
    RunFloatLifecycleAbyRound(parties, algorithm, operation.name, a, b);
    result.round_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ResetAllFloatLifecycleParties(parties);
    result.reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);
  }

  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    total_transport_statistics.at(party_id) =
        parties.at(party_id)->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
  }

  stage_start = std::chrono::steady_clock::now();
  FinishAllFloatLifecycleParties(parties);
  result.cleanup_finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  CollectFloatLifecycleCommunicationStatistics(total_transport_statistics,
                                               result.communication_statistics,
                                               accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.round_run_ms + result.reset_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

FloatLifecycleBenchmarkResult BenchmarkFloatLifecycleUsingFinish(
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t number_of_parties,
    std::size_t rounds, AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  FloatLifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();
  auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf10a7ULL);

  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);

  for (std::size_t round = 0; round < rounds; ++round) {
    const auto [a, b] = MakeFloatLifecycleInputs(generator, operation.name);

    auto stage_start = std::chrono::steady_clock::now();
    auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
    result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ConfigurePartiesForPerformance(parties);
    result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    RunFloatLifecycleAbyRound(parties, algorithm, operation.name, a, b);
    result.round_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    FinishAllFloatLifecycleParties(parties);
    result.finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);
    AccumulateFloatLifecycleRoundTransportStatistics(total_transport_statistics, parties);
  }

  CollectFloatLifecycleCommunicationStatistics(total_transport_statistics,
                                               result.communication_statistics,
                                               accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.round_run_ms + result.finish_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

FloatInputPassLifecycleBenchmarkResult BenchmarkFloatLifecycleInputPassesUsingReset(
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t number_of_parties,
    std::size_t rounds, AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  FloatInputPassLifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();
  auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf10a7ULL);

  auto stage_start = std::chrono::steady_clock::now();
  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  stage_start = std::chrono::steady_clock::now();
  ConfigurePartiesForPerformance(parties);
  result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  for (std::size_t round = 0; round < rounds; ++round) {
    const auto [a, b] = MakeFloatLifecycleInputs(generator, operation.name);

    stage_start = std::chrono::steady_clock::now();
    auto share_a_by_party =
        RunFloatLifecycleInputPassAndKeepShares(parties, std::bit_cast<std::uint64_t>(a), 0);
    result.input_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ResetAllFloatLifecycleParties(parties);
    result.input_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);

    stage_start = std::chrono::steady_clock::now();
    auto share_b_by_party =
        RunFloatLifecycleInputPassAndKeepShares(parties, std::bit_cast<std::uint64_t>(b), 1);
    result.input_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ResetAllFloatLifecycleParties(parties);
    result.input_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);

    stage_start = std::chrono::steady_clock::now();
    RunFloatLifecycleAbyRoundWithShares(parties, algorithm, operation.name, a, b,
                                        share_a_by_party, share_b_by_party);
    result.add_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ResetAllFloatLifecycleParties(parties);
    result.add_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);
  }

  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    total_transport_statistics.at(party_id) =
        parties.at(party_id)->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
  }

  stage_start = std::chrono::steady_clock::now();
  FinishAllFloatLifecycleParties(parties);
  result.cleanup_finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

  CollectFloatLifecycleCommunicationStatistics(total_transport_statistics,
                                               result.communication_statistics,
                                               accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.input_run_ms +
                    result.input_reset_ms + result.add_run_ms + result.add_reset_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

FloatInputPassLifecycleBenchmarkResult BenchmarkFloatLifecycleInputPassesUsingFinish(
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t number_of_parties,
    std::size_t rounds, AccumulatedRunTimeStatistics* accumulated_run_time_statistics = nullptr,
    AccumulatedCommunicationStatistics* accumulated_communication_statistics = nullptr) {
  FloatInputPassLifecycleBenchmarkResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();
  auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf10a7ULL);
  std::vector<std::vector<encrypto::motion::communication::TransportStatistics>>
      total_transport_statistics(number_of_parties);

  const auto run_input_pass = [&](std::uint64_t input, std::size_t input_owner) {
    auto stage_start = std::chrono::steady_clock::now();
    auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
    result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ConfigurePartiesForPerformance(parties);
    result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    RunFloatLifecycleInputPass(parties, input, input_owner);
    result.input_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    FinishAllFloatLifecycleParties(parties);
    result.input_finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);
    AccumulateFloatLifecycleRoundTransportStatistics(total_transport_statistics, parties);
  };

  for (std::size_t round = 0; round < rounds; ++round) {
    const auto [a, b] = MakeFloatLifecycleInputs(generator, operation.name);

    run_input_pass(std::bit_cast<std::uint64_t>(a), 0);
    run_input_pass(std::bit_cast<std::uint64_t>(b), 1);

    auto stage_start = std::chrono::steady_clock::now();
    auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
    result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    ConfigurePartiesForPerformance(parties);
    result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    RunFloatLifecycleAbyRound(parties, algorithm, operation.name, a, b);
    result.add_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    FinishAllFloatLifecycleParties(parties);
    result.add_finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    CollectFloatLifecycleRunTimeStatistics(parties, result.run_time_statistics,
                                           accumulated_run_time_statistics);
    AccumulateFloatLifecycleRoundTransportStatistics(total_transport_statistics, parties);
  }

  CollectFloatLifecycleCommunicationStatistics(total_transport_statistics,
                                               result.communication_statistics,
                                               accumulated_communication_statistics);

  result.total_ms = result.party_create_ms + result.configure_ms + result.input_run_ms +
                    result.input_finish_ms + result.add_run_ms + result.add_finish_ms;
  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

#ifndef _WIN32
struct FloatTcpProcessPartyResult {
  double party_create_ms{0.0};
  double configure_ms{0.0};
  double input_run_ms{0.0};
  double input_reset_ms{0.0};
  double add_run_ms{0.0};
  double add_reset_ms{0.0};
  double finish_ms{0.0};
  double wall_total_ms{0.0};
  double messages_sent{0.0};
  double messages_received{0.0};
  double bytes_sent{0.0};
  double bytes_received{0.0};
  double tcp_send_time_ms{0.0};
  double tcp_receive_time_ms{0.0};
  double tcp_receive_wait_time_ms{0.0};
  double tcp_receive_message_size_time_ms{0.0};
  double tcp_receive_payload_time_ms{0.0};
  int status{0};
};

bool WriteFull(int fd, const void* data, std::size_t size) {
  const auto* cursor = static_cast<const char*>(data);
  while (size > 0) {
    const auto written = ::write(fd, cursor, size);
    if (written <= 0) {
      return false;
    }
    cursor += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

bool ReadFull(int fd, void* data, std::size_t size) {
  auto* cursor = static_cast<char*>(data);
  while (size > 0) {
    const auto bytes_read = ::read(fd, cursor, size);
    if (bytes_read <= 0) {
      return false;
    }
    cursor += bytes_read;
    size -= static_cast<std::size_t>(bytes_read);
  }
  return true;
}

std::unique_ptr<Party> MakeTcpProcessParty(std::size_t party_id, std::size_t number_of_parties,
                                           std::uint16_t base_port) {
  encrypto::motion::communication::TcpPartiesConfiguration configuration(number_of_parties);
  for (std::size_t id = 0; id < number_of_parties; ++id) {
    configuration.at(id) =
        std::make_pair(std::string("127.0.0.1"), static_cast<std::uint16_t>(base_port + id));
  }

  encrypto::motion::communication::TcpSetupHelper helper(party_id, configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      party_id, helper.SetupConnections());
  return std::make_unique<Party>(std::move(communication_layer));
}

encrypto::motion::ShareWrapper RunSingleFloatLifecycleInputPassAndKeepShare(
    Party& party, std::size_t party_id, std::uint64_t input, std::size_t input_owner) {
  constexpr auto kProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;

  const auto input_bits = encrypto::motion::ToInput(input);
  const std::vector<BitVector<>> zero_bits(input_bits.size(), BitVector<>(1, false));
  auto local_input = (party_id == input_owner) ? input_bits : zero_bits;
  encrypto::motion::ShareWrapper share(
      party.In<kProtocol>(std::move(local_input), input_owner));
  party.Run();
  return share;
}

bool RunSingleFloatLifecycleAbyRoundWithShares(
    Party& party, std::size_t party_id, const encrypto::motion::AlgorithmDescription& algorithm,
    const std::string& op, double a, double b, const encrypto::motion::ShareWrapper& share_a,
    const encrypto::motion::ShareWrapper& share_b) {
  const auto concatenated = encrypto::motion::ShareWrapper::Concatenate(
      std::vector<encrypto::motion::ShareWrapper>{share_a, share_b});
  auto output = concatenated.Evaluate(algorithm).Out(0);

  party.Run();
  if (party_id != 0) {
    return true;
  }

  const auto opened_output = output.As<std::vector<BitVector<>>>();
  if (opened_output.size() != 64u) {
    return false;
  }
  const auto result_bits = encrypto::motion::ToOutput<std::uint64_t>(opened_output);
  const auto expected_bits =
      std::bit_cast<std::uint64_t>(ComputeFloatLifecycleExpected(op, a, b));
  return result_bits == expected_bits;
}

void AddTcpProcessTransportStatistics(FloatTcpProcessPartyResult& result,
                                      const std::vector<
                                          encrypto::motion::communication::TransportStatistics>&
                                          transport_statistics) {
  constexpr double kNanosecondsPerMillisecond = 1'000'000.0;
  for (const auto& peer_statistics : transport_statistics) {
    result.messages_sent +=
        static_cast<double>(peer_statistics.number_of_messages_sent);
    result.messages_received +=
        static_cast<double>(peer_statistics.number_of_messages_received);
    result.bytes_sent += static_cast<double>(peer_statistics.number_of_bytes_sent);
    result.bytes_received +=
        static_cast<double>(peer_statistics.number_of_bytes_received);
    result.tcp_send_time_ms +=
        static_cast<double>(peer_statistics.send_time_ns) / kNanosecondsPerMillisecond;
    result.tcp_receive_time_ms +=
        static_cast<double>(peer_statistics.receive_time_ns) / kNanosecondsPerMillisecond;
    result.tcp_receive_wait_time_ms +=
        static_cast<double>(peer_statistics.receive_wait_time_ns) / kNanosecondsPerMillisecond;
    result.tcp_receive_message_size_time_ms +=
        static_cast<double>(peer_statistics.receive_message_size_time_ns) /
        kNanosecondsPerMillisecond;
    result.tcp_receive_payload_time_ms +=
        static_cast<double>(peer_statistics.receive_payload_time_ns) /
        kNanosecondsPerMillisecond;
  }
}

FloatTcpProcessPartyResult RunFloatTcpProcessParty(
    std::size_t party_id, std::size_t number_of_parties, std::uint16_t base_port,
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t rounds) {
  FloatTcpProcessPartyResult result;
  const auto wall_total_start = std::chrono::steady_clock::now();
  try {
    auto stage_start = std::chrono::steady_clock::now();
    auto party = MakeTcpProcessParty(party_id, number_of_parties, base_port);
    result.party_create_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    stage_start = std::chrono::steady_clock::now();
    party->GetLogger()->SetEnabled(false);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
    result.configure_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

    auto generator = MakeFloatRandomGenerator(number_of_parties, 0xf10a7ULL);
    bool output_ok = true;
    for (std::size_t round = 0; round < rounds; ++round) {
      const auto [a, b] = MakeFloatLifecycleInputs(generator, operation.name);

      stage_start = std::chrono::steady_clock::now();
      auto share_a = RunSingleFloatLifecycleInputPassAndKeepShare(
          *party, party_id, std::bit_cast<std::uint64_t>(a), 0);
      result.input_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

      stage_start = std::chrono::steady_clock::now();
      party->Reset();
      result.input_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

      stage_start = std::chrono::steady_clock::now();
      auto share_b = RunSingleFloatLifecycleInputPassAndKeepShare(
          *party, party_id, std::bit_cast<std::uint64_t>(b), 1);
      result.input_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

      stage_start = std::chrono::steady_clock::now();
      party->Reset();
      result.input_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

      stage_start = std::chrono::steady_clock::now();
      output_ok &= RunSingleFloatLifecycleAbyRoundWithShares(
          *party, party_id, algorithm, operation.name, a, b, share_a, share_b);
      result.add_run_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);

      stage_start = std::chrono::steady_clock::now();
      party->Reset();
      result.add_reset_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
    }

    AddTcpProcessTransportStatistics(
        result, party->GetBackend()->GetCommunicationLayer().GetTransportStatistics());

    stage_start = std::chrono::steady_clock::now();
    party->Finish();
    result.finish_ms += ToMilliseconds(std::chrono::steady_clock::now() - stage_start);
    result.status = output_ok ? 0 : 2;
  } catch (const std::exception&) {
    result.status = 1;
  }

  result.wall_total_ms = ToMilliseconds(std::chrono::steady_clock::now() - wall_total_start);
  return result;
}

FloatTcpProcessLifecycleBenchmarkResult CombineTcpProcessPartyResults(
    const std::vector<FloatTcpProcessPartyResult>& party_results, double parent_wall_total_ms) {
  FloatTcpProcessLifecycleBenchmarkResult result;
  const auto max_field = [&](double FloatTcpProcessPartyResult::*field) {
    double value = 0.0;
    for (const auto& party_result : party_results) {
      value = std::max(value, party_result.*field);
    }
    return value;
  };

  result.party_create_ms = max_field(&FloatTcpProcessPartyResult::party_create_ms);
  result.configure_ms = max_field(&FloatTcpProcessPartyResult::configure_ms);
  result.input_run_ms = max_field(&FloatTcpProcessPartyResult::input_run_ms);
  result.input_reset_ms = max_field(&FloatTcpProcessPartyResult::input_reset_ms);
  result.add_run_ms = max_field(&FloatTcpProcessPartyResult::add_run_ms);
  result.add_reset_ms = max_field(&FloatTcpProcessPartyResult::add_reset_ms);
  result.finish_ms = max_field(&FloatTcpProcessPartyResult::finish_ms);
  result.wall_total_ms = parent_wall_total_ms;
  result.total_ms = result.party_create_ms + result.configure_ms + result.input_run_ms +
                    result.input_reset_ms + result.add_run_ms + result.add_reset_ms;

  for (const auto& party_result : party_results) {
    result.messages_sent += party_result.messages_sent;
    result.messages_received += party_result.messages_received;
    result.bytes_sent += party_result.bytes_sent;
    result.bytes_received += party_result.bytes_received;
    result.tcp_send_time_ms += party_result.tcp_send_time_ms;
    result.tcp_receive_time_ms += party_result.tcp_receive_time_ms;
    result.tcp_receive_wait_time_ms += party_result.tcp_receive_wait_time_ms;
    result.tcp_receive_message_size_time_ms +=
        party_result.tcp_receive_message_size_time_ms;
    result.tcp_receive_payload_time_ms += party_result.tcp_receive_payload_time_ms;
  }
  return result;
}

FloatTcpProcessLifecycleBenchmarkResult BenchmarkFloatLifecycleTcpProcessesUsingReset(
    const FloatLifecycleOperation& operation,
    const encrypto::motion::AlgorithmDescription& algorithm, std::size_t number_of_parties,
    std::size_t rounds, std::uint16_t base_port) {
  std::vector<std::array<int, 2>> pipes(number_of_parties);
  for (auto& pipe_fds : pipes) {
    if (::pipe(pipe_fds.data()) != 0) {
      throw std::runtime_error("failed to create pipe for TCP process benchmark");
    }
  }

  std::vector<pid_t> child_pids(number_of_parties, -1);
  const auto parent_wall_start = std::chrono::steady_clock::now();
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    const auto pid = ::fork();
    if (pid < 0) {
      throw std::runtime_error("failed to fork TCP benchmark child process");
    }
    if (pid == 0) {
      for (std::size_t i = 0; i < pipes.size(); ++i) {
        ::close(pipes.at(i).at(0));
        if (i != party_id) {
          ::close(pipes.at(i).at(1));
        }
      }

      const auto party_result = RunFloatTcpProcessParty(
          party_id, number_of_parties, base_port, operation, algorithm, rounds);
      const auto wrote_result =
          WriteFull(pipes.at(party_id).at(1), &party_result, sizeof(party_result));
      ::close(pipes.at(party_id).at(1));
      ::_exit((wrote_result && party_result.status == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    child_pids.at(party_id) = pid;
  }

  for (auto& pipe_fds : pipes) {
    ::close(pipe_fds.at(1));
  }

  std::vector<FloatTcpProcessPartyResult> party_results(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    if (!ReadFull(pipes.at(party_id).at(0), &party_results.at(party_id),
                  sizeof(party_results.at(party_id)))) {
      throw std::runtime_error("failed to read TCP benchmark child result");
    }
    ::close(pipes.at(party_id).at(0));
  }

  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    int wait_status = 0;
    if (::waitpid(child_pids.at(party_id), &wait_status, 0) != child_pids.at(party_id)) {
      throw std::runtime_error("failed to wait for TCP benchmark child process");
    }
    if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != EXIT_SUCCESS ||
        party_results.at(party_id).status != 0) {
      throw std::runtime_error("TCP benchmark child process failed");
    }
  }

  const auto parent_wall_total_ms =
      ToMilliseconds(std::chrono::steady_clock::now() - parent_wall_start);
  return CombineTcpProcessPartyResults(party_results, parent_wall_total_ms);
}
#endif

TEST(FloatMpc64Lifecycle, FromAbyTcpProcessVsDummyCommunication) {
#ifdef _WIN32
  GTEST_SKIP() << "TCP process benchmark uses fork/pipe and is only available on POSIX";
#else
  constexpr std::size_t kNumberOfTcpProcesses = 3;
  const auto operation = GetFloatLifecycleOperation();
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      std::string(encrypto::motion::kRootDir) + "/" + operation.relative_path);
  const auto rounds = GetEnvSizeT("MOTION_FLOAT_COMM_ROUNDS",
                                  GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_ROUNDS", 1));
  const auto trial_count = GetEnvSizeT("MOTION_FLOAT_COMM_TRIALS",
                                       GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_TRIALS", 1));
  const auto warmup_trial_count = GetEnvSizeTAllowZero(
      "MOTION_FLOAT_COMM_WARMUP_TRIALS",
      GetEnvSizeTAllowZero("MOTION_FLOAT_LIFECYCLE_WARMUP_TRIALS", 0));
  const auto base_port_value =
      GetEnvSizeT("MOTION_FLOAT_TCP_PROCESS_BASE_PORT", 23000);
  const auto port_span = (trial_count + warmup_trial_count + 1) * (kNumberOfTcpProcesses + 1);
  if (base_port_value + port_span > std::numeric_limits<std::uint16_t>::max()) {
    throw std::invalid_argument("MOTION_FLOAT_TCP_PROCESS_BASE_PORT is too high for trial count");
  }

  std::vector<FloatInputPassLifecycleBenchmarkResult> dummy_results;
  std::vector<FloatTcpProcessLifecycleBenchmarkResult> tcp_process_results;
  dummy_results.reserve(trial_count);
  tcp_process_results.reserve(trial_count);

  AccumulatedRunTimeStatistics dummy_accumulated_run_time_statistics;
  AccumulatedCommunicationStatistics dummy_accumulated_communication_statistics;
  std::size_t tcp_invocation = 0;
  const auto run_tcp_process_benchmark = [&] {
    const auto base_port = static_cast<std::uint16_t>(
        base_port_value + tcp_invocation++ * (kNumberOfTcpProcesses + 1));
    return BenchmarkFloatLifecycleTcpProcessesUsingReset(
        operation, algorithm, kNumberOfTcpProcesses, rounds, base_port);
  };

  for (std::size_t warmup_trial = 0; warmup_trial < warmup_trial_count; ++warmup_trial) {
    if ((warmup_trial % 2) == 0) {
      (void)BenchmarkFloatLifecycleInputPassesUsingReset(
          operation, algorithm, kNumberOfTcpProcesses, rounds);
      (void)run_tcp_process_benchmark();
    } else {
      (void)run_tcp_process_benchmark();
      (void)BenchmarkFloatLifecycleInputPassesUsingReset(
          operation, algorithm, kNumberOfTcpProcesses, rounds);
    }
  }

  for (std::size_t trial = 0; trial < trial_count; ++trial) {
    const auto run_dummy = [&] {
      dummy_results.emplace_back(BenchmarkFloatLifecycleInputPassesUsingReset(
          operation, algorithm, kNumberOfTcpProcesses, rounds,
          &dummy_accumulated_run_time_statistics,
          &dummy_accumulated_communication_statistics));
    };
    const auto run_tcp = [&] {
      tcp_process_results.emplace_back(run_tcp_process_benchmark());
    };

    if ((trial % 2) == 0) {
      run_dummy();
      run_tcp();
    } else {
      run_tcp();
      run_dummy();
    }
  }

  const auto dummy_name =
      "Float64 FromAby " + operation.name +
      " dummy in-process [(In a+Run+Reset)+(In b+Run+Reset)+Add(old shares)+Run+Reset]x" +
      std::to_string(rounds) + " (" + std::to_string(kNumberOfTcpProcesses) +
      " parties, " + std::to_string(trial_count) + " measured trials, " +
      std::to_string(warmup_trial_count) + " warmup trials excluded)";
  std::cout << PrintStatistics(dummy_name, dummy_accumulated_run_time_statistics,
                               dummy_accumulated_communication_statistics);

  const auto dummy_total_median =
      Median(CollectField(dummy_results, &FloatInputPassLifecycleBenchmarkResult::total_ms));
  const auto tcp_total_median =
      Median(CollectField(tcp_process_results, &FloatTcpProcessLifecycleBenchmarkResult::total_ms));
  const auto tcp_wall_total_median = Median(
      CollectField(tcp_process_results, &FloatTcpProcessLifecycleBenchmarkResult::wall_total_ms));
  const auto ratio = dummy_total_median > 0.0 ? tcp_total_median / dummy_total_median : 0.0;

  std::cout << "Float64 FromAby communication comparable total median (ms): op="
            << operation.name << ", parties=" << kNumberOfTcpProcesses
            << ", rounds=" << rounds << ", trials=" << trial_count
            << ", dummy_in_process_total_median=" << dummy_total_median
            << ", tcp_3_process_total_median=" << tcp_total_median
            << ", tcp/dummy=" << ratio
            << ", dummy_per_add=" << (dummy_total_median / rounds)
            << ", tcp_per_add=" << (tcp_total_median / rounds)
            << ", tcp_parent_wall_total_median=" << tcp_wall_total_median << "\n";
  std::cout << "Float64 FromAby communication stage medians dummy(ms): create="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::party_create_ms))
            << ", configure="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::configure_ms))
            << ", input_run="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::input_run_ms))
            << ", input_reset="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::input_reset_ms))
            << ", add_run="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::add_run_ms))
            << ", add_reset="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::add_reset_ms))
            << ", cleanup_finish(excluded)="
            << Median(CollectField(dummy_results,
                                   &FloatInputPassLifecycleBenchmarkResult::cleanup_finish_ms))
            << "\n";
  std::cout << "Float64 FromAby communication stage medians tcp_3_process(ms): create="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::party_create_ms))
            << ", configure="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::configure_ms))
            << ", input_run="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::input_run_ms))
            << ", input_reset="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::input_reset_ms))
            << ", add_run="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::add_run_ms))
            << ", add_reset="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::add_reset_ms))
            << ", finish(excluded)="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::finish_ms))
            << "\n";
  std::cout << "Float64 FromAby tcp_3_process communication median totals: messages_sent="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::messages_sent))
            << ", messages_received="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::messages_received))
            << ", bytes_sent="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::bytes_sent))
            << ", bytes_received="
            << Median(CollectField(tcp_process_results,
                                   &FloatTcpProcessLifecycleBenchmarkResult::bytes_received))
            << "\n";

  const auto tcp_send_time_median = Median(CollectField(
      tcp_process_results, &FloatTcpProcessLifecycleBenchmarkResult::tcp_send_time_ms));
  const auto tcp_receive_time_median = Median(CollectField(
      tcp_process_results, &FloatTcpProcessLifecycleBenchmarkResult::tcp_receive_time_ms));
  const auto tcp_receive_wait_time_median = Median(CollectField(
      tcp_process_results, &FloatTcpProcessLifecycleBenchmarkResult::tcp_receive_wait_time_ms));
  const auto tcp_receive_message_size_time_median = Median(CollectField(
      tcp_process_results,
      &FloatTcpProcessLifecycleBenchmarkResult::tcp_receive_message_size_time_ms));
  const auto tcp_receive_payload_time_median = Median(CollectField(
      tcp_process_results,
      &FloatTcpProcessLifecycleBenchmarkResult::tcp_receive_payload_time_ms));
  const auto tcp_send_receive_time_median =
      tcp_send_time_median + tcp_receive_time_median;

  std::cout << "Float64 FromAby tcp_3_process transport timing median totals(ms): send="
            << tcp_send_time_median << ", receive_total=" << tcp_receive_time_median
            << ", receive_wait=" << tcp_receive_wait_time_median
            << ", receive_message_size=" << tcp_receive_message_size_time_median
            << ", receive_payload=" << tcp_receive_payload_time_median
            << ", send_plus_receive=" << tcp_send_receive_time_median << "\n";
  std::cout << "Float64 FromAby tcp_3_process transport timing per add(ms): send="
            << (tcp_send_time_median / rounds)
            << ", receive_total=" << (tcp_receive_time_median / rounds)
            << ", receive_wait=" << (tcp_receive_wait_time_median / rounds)
            << ", receive_message_size="
            << (tcp_receive_message_size_time_median / rounds)
            << ", receive_payload=" << (tcp_receive_payload_time_median / rounds)
            << ", send_plus_receive=" << (tcp_send_receive_time_median / rounds) << "\n";

  EXPECT_GT(dummy_total_median, 0.0);
  EXPECT_GT(tcp_total_median, 0.0);
#endif
}

TEST(FloatMpc64Lifecycle, FromAbyResetVsFinish) {
  const auto operation = GetFloatLifecycleOperation();
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      std::string(encrypto::motion::kRootDir) + "/" + operation.relative_path);
  const auto rounds = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_ROUNDS", 3);
  const auto trial_count = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_TRIALS", 1);
  const auto warmup_trial_count = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_WARMUP_TRIALS", 1);

  for (const auto number_of_parties : GetFloatLifecyclePartyCounts()) {
    std::vector<FloatLifecycleBenchmarkResult> reset_results;
    std::vector<FloatLifecycleBenchmarkResult> finish_results;
    reset_results.reserve(trial_count);
    finish_results.reserve(trial_count);

    AccumulatedRunTimeStatistics reset_accumulated_run_time_statistics;
    AccumulatedRunTimeStatistics finish_accumulated_run_time_statistics;
    AccumulatedCommunicationStatistics reset_accumulated_communication_statistics;
    AccumulatedCommunicationStatistics finish_accumulated_communication_statistics;

    for (std::size_t warmup_trial = 0; warmup_trial < warmup_trial_count; ++warmup_trial) {
      if ((warmup_trial % 2) == 0) {
        (void)BenchmarkFloatLifecycleUsingReset(operation, algorithm, number_of_parties, rounds);
        (void)BenchmarkFloatLifecycleUsingFinish(operation, algorithm, number_of_parties, rounds);
      } else {
        (void)BenchmarkFloatLifecycleUsingFinish(operation, algorithm, number_of_parties, rounds);
        (void)BenchmarkFloatLifecycleUsingReset(operation, algorithm, number_of_parties, rounds);
      }
    }

    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto run_reset = [&] {
        reset_results.emplace_back(BenchmarkFloatLifecycleUsingReset(
            operation, algorithm, number_of_parties, rounds, &reset_accumulated_run_time_statistics,
            &reset_accumulated_communication_statistics));
      };
      const auto run_finish = [&] {
        finish_results.emplace_back(BenchmarkFloatLifecycleUsingFinish(
            operation, algorithm, number_of_parties, rounds,
            &finish_accumulated_run_time_statistics,
            &finish_accumulated_communication_statistics));
      };

      if ((trial % 2) == 0) {
        run_reset();
        run_finish();
      } else {
        run_finish();
        run_reset();
      }
    }

    const auto reset_name =
        "Float64 FromAby " + operation.name + " Create+Configure+(Run+Reset)x" +
        std::to_string(rounds) + " (" + std::to_string(number_of_parties) +
        " parties, " + std::to_string(trial_count) + " measured trials, " +
        std::to_string(warmup_trial_count) + " warmup trials excluded, interleaved)";
    const auto finish_name =
        "Float64 FromAby " + operation.name +
        " Create+Configure+(Run+Finish)x" + std::to_string(rounds) +
        " fresh parties each round (" + std::to_string(number_of_parties) +
        " parties, " + std::to_string(trial_count) + " measured trials, " +
        std::to_string(warmup_trial_count) + " warmup trials excluded, interleaved)";

    std::cout << PrintStatistics(reset_name, reset_accumulated_run_time_statistics,
                                 reset_accumulated_communication_statistics);
    std::cout << PrintStatistics(finish_name, finish_accumulated_run_time_statistics,
                                 finish_accumulated_communication_statistics);

    const auto reset_total_median =
        Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::total_ms));
    const auto finish_total_median =
        Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::total_ms));
    const auto ratio = finish_total_median > 0.0 ? reset_total_median / finish_total_median : 0.0;
    const auto reset_wall_total_median =
        Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::wall_total_ms));
    const auto finish_wall_total_median =
        Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::wall_total_ms));

    std::cout << "Float64 FromAby lifecycle comparable total median (ms): op="
              << operation.name << ", parties=" << number_of_parties << ", rounds=" << rounds
              << ", trials=" << trial_count
              << ", reset_total_median=" << reset_total_median
              << ", finish_total_median=" << finish_total_median
              << ", reset/finish=" << ratio << "\n";
    std::cout << "Float64 FromAby lifecycle wall total median (ms): op=" << operation.name
              << ", parties=" << number_of_parties
              << ", reset_wall_total_median=" << reset_wall_total_median
              << ", finish_wall_total_median=" << finish_wall_total_median << "\n";
    std::cout << "Float64 FromAby lifecycle stage medians reset(ms): create="
              << Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::party_create_ms))
              << ", configure="
              << Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::configure_ms))
              << ", run="
              << Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::round_run_ms))
              << ", reset="
              << Median(CollectField(reset_results, &FloatLifecycleBenchmarkResult::reset_ms))
              << ", cleanup_finish(excluded)="
              << Median(
                     CollectField(reset_results,
                                  &FloatLifecycleBenchmarkResult::cleanup_finish_ms))
              << "\n";
    std::cout << "Float64 FromAby lifecycle stage medians finish(ms): create="
              << Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::party_create_ms))
              << ", configure="
              << Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::configure_ms))
              << ", run="
              << Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::round_run_ms))
              << ", finish="
              << Median(CollectField(finish_results, &FloatLifecycleBenchmarkResult::finish_ms))
              << "\n";

    EXPECT_GT(reset_total_median, 0.0);
    EXPECT_GT(finish_total_median, 0.0);
  }
}

TEST(FloatMpc64Lifecycle, FromAbyInputPassResetVsFinish) {
  const auto operation = GetFloatLifecycleOperation();
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(
      std::string(encrypto::motion::kRootDir) + "/" + operation.relative_path);
  const auto rounds = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_ROUNDS", 3);
  const auto trial_count = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_TRIALS", 1);
  const auto warmup_trial_count = GetEnvSizeT("MOTION_FLOAT_LIFECYCLE_WARMUP_TRIALS", 1);

  for (const auto number_of_parties : GetFloatLifecyclePartyCounts()) {
    std::vector<FloatInputPassLifecycleBenchmarkResult> reset_results;
    std::vector<FloatInputPassLifecycleBenchmarkResult> finish_results;
    reset_results.reserve(trial_count);
    finish_results.reserve(trial_count);

    AccumulatedRunTimeStatistics reset_accumulated_run_time_statistics;
    AccumulatedRunTimeStatistics finish_accumulated_run_time_statistics;
    AccumulatedCommunicationStatistics reset_accumulated_communication_statistics;
    AccumulatedCommunicationStatistics finish_accumulated_communication_statistics;

    for (std::size_t warmup_trial = 0; warmup_trial < warmup_trial_count; ++warmup_trial) {
      if ((warmup_trial % 2) == 0) {
        (void)BenchmarkFloatLifecycleInputPassesUsingReset(operation, algorithm,
                                                           number_of_parties, rounds);
        (void)BenchmarkFloatLifecycleInputPassesUsingFinish(operation, algorithm,
                                                            number_of_parties, rounds);
      } else {
        (void)BenchmarkFloatLifecycleInputPassesUsingFinish(operation, algorithm,
                                                            number_of_parties, rounds);
        (void)BenchmarkFloatLifecycleInputPassesUsingReset(operation, algorithm,
                                                           number_of_parties, rounds);
      }
    }

    for (std::size_t trial = 0; trial < trial_count; ++trial) {
      const auto run_reset = [&] {
        reset_results.emplace_back(BenchmarkFloatLifecycleInputPassesUsingReset(
            operation, algorithm, number_of_parties, rounds, &reset_accumulated_run_time_statistics,
            &reset_accumulated_communication_statistics));
      };
      const auto run_finish = [&] {
        finish_results.emplace_back(BenchmarkFloatLifecycleInputPassesUsingFinish(
            operation, algorithm, number_of_parties, rounds,
            &finish_accumulated_run_time_statistics,
            &finish_accumulated_communication_statistics));
      };

      if ((trial % 2) == 0) {
        run_reset();
        run_finish();
      } else {
        run_finish();
        run_reset();
      }
    }

    const auto reset_name =
        "Float64 FromAby " + operation.name +
        " [(In a share+Run+Reset)+(In b share+Run+Reset)+Add(old shares)+Run+Reset]x" +
        std::to_string(rounds) + " (" + std::to_string(number_of_parties) +
        " parties, " + std::to_string(trial_count) + " measured trials, " +
        std::to_string(warmup_trial_count) + " warmup trials excluded, interleaved)";
    const auto finish_name =
        "Float64 FromAby " + operation.name +
        " [(In a+Run+Finish)+(In b+Run+Finish)+Add+Run+Finish]x" +
        std::to_string(rounds) + " fresh parties per pass (" +
        std::to_string(number_of_parties) + " parties, " + std::to_string(trial_count) +
        " measured trials, " + std::to_string(warmup_trial_count) +
        " warmup trials excluded, interleaved)";

    std::cout << PrintStatistics(reset_name, reset_accumulated_run_time_statistics,
                                 reset_accumulated_communication_statistics);
    std::cout << PrintStatistics(finish_name, finish_accumulated_run_time_statistics,
                                 finish_accumulated_communication_statistics);

    const auto collect_sum = [](const auto& results, auto first_field, auto second_field) {
      std::vector<double> values;
      values.reserve(results.size());
      for (const auto& result : results) {
        values.push_back(result.*first_field + result.*second_field);
      }
      return values;
    };

    const auto reset_total_median =
        Median(CollectField(reset_results, &FloatInputPassLifecycleBenchmarkResult::total_ms));
    const auto finish_total_median =
        Median(CollectField(finish_results, &FloatInputPassLifecycleBenchmarkResult::total_ms));
    const auto ratio = finish_total_median > 0.0 ? reset_total_median / finish_total_median : 0.0;
    const auto reset_input_extra_median = Median(collect_sum(
        reset_results, &FloatInputPassLifecycleBenchmarkResult::input_run_ms,
        &FloatInputPassLifecycleBenchmarkResult::input_reset_ms));
    const auto finish_input_extra_median = Median(collect_sum(
        finish_results, &FloatInputPassLifecycleBenchmarkResult::input_run_ms,
        &FloatInputPassLifecycleBenchmarkResult::input_finish_ms));
    const auto reset_input_reset_median =
        Median(CollectField(reset_results, &FloatInputPassLifecycleBenchmarkResult::input_reset_ms));
    const auto reset_add_reset_median =
        Median(CollectField(reset_results, &FloatInputPassLifecycleBenchmarkResult::add_reset_ms));
    const auto finish_reconstruct_median =
        Median(collect_sum(finish_results, &FloatInputPassLifecycleBenchmarkResult::party_create_ms,
                           &FloatInputPassLifecycleBenchmarkResult::configure_ms));

    std::cout << "Float64 FromAby pre-input lifecycle comparable total median (ms): op="
              << operation.name << ", parties=" << number_of_parties << ", rounds=" << rounds
              << ", trials=" << trial_count << ", reset_total_median=" << reset_total_median
              << ", finish_total_median=" << finish_total_median << ", reset/finish=" << ratio
              << "\n";
    std::cout << "Float64 FromAby pre-input reset pass overhead median (ms): op="
              << operation.name << ", parties=" << number_of_parties
              << ", input_run_plus_reset_total=" << reset_input_extra_median
              << ", input_reset_total=" << reset_input_reset_median
              << ", input_reset_per_fromaby_add=" << (reset_input_reset_median / rounds)
              << ", input_reset_per_input_pass=" << (reset_input_reset_median / (2.0 * rounds))
              << ", add_reset_total=" << reset_add_reset_median
              << ", add_reset_per_fromaby_add=" << (reset_add_reset_median / rounds) << "\n";
    std::cout << "Float64 FromAby pre-input finish pass median (ms): op=" << operation.name
              << ", parties=" << number_of_parties
              << ", input_run_plus_finish_total=" << finish_input_extra_median
              << ", reconstruct_create_plus_configure_total=" << finish_reconstruct_median
              << "\n";
    std::cout << "Float64 FromAby pre-input stage medians reset(ms): create="
              << Median(
                     CollectField(reset_results,
                                  &FloatInputPassLifecycleBenchmarkResult::party_create_ms))
              << ", configure="
              << Median(CollectField(reset_results,
                                      &FloatInputPassLifecycleBenchmarkResult::configure_ms))
              << ", input_run="
              << Median(CollectField(reset_results,
                                      &FloatInputPassLifecycleBenchmarkResult::input_run_ms))
              << ", input_reset="
              << reset_input_reset_median << ", add_run="
              << Median(
                     CollectField(reset_results,
                                  &FloatInputPassLifecycleBenchmarkResult::add_run_ms))
              << ", add_reset=" << reset_add_reset_median
              << ", cleanup_finish(excluded)="
              << Median(
                     CollectField(reset_results,
                                  &FloatInputPassLifecycleBenchmarkResult::cleanup_finish_ms))
              << "\n";
    std::cout << "Float64 FromAby pre-input stage medians finish(ms): create="
              << Median(
                     CollectField(finish_results,
                                  &FloatInputPassLifecycleBenchmarkResult::party_create_ms))
              << ", configure="
              << Median(CollectField(finish_results,
                                      &FloatInputPassLifecycleBenchmarkResult::configure_ms))
              << ", input_run="
              << Median(CollectField(finish_results,
                                      &FloatInputPassLifecycleBenchmarkResult::input_run_ms))
              << ", input_finish="
              << Median(CollectField(finish_results,
                                      &FloatInputPassLifecycleBenchmarkResult::input_finish_ms))
              << ", add_run="
              << Median(
                     CollectField(finish_results,
                                  &FloatInputPassLifecycleBenchmarkResult::add_run_ms))
              << ", add_finish="
              << Median(CollectField(finish_results,
                                      &FloatInputPassLifecycleBenchmarkResult::add_finish_ms))
              << "\n";

    EXPECT_GT(reset_total_median, 0.0);
    EXPECT_GT(finish_total_median, 0.0);
  }
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

