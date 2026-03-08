// MIT License

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "test_constants.h"
#include "utility/bit_vector.h"
#include "utility/config.h"

namespace {

using encrypto::motion::AccumulatedCommunicationStatistics;
using encrypto::motion::AccumulatedRunTimeStatistics;
using encrypto::motion::BitVector;
using encrypto::motion::Party;
using encrypto::motion::PrintStatistics;

constexpr auto kAesProtocol = encrypto::motion::MpcProtocol::kBooleanGmw;
constexpr std::array<std::size_t, 4> kAesPartyCounts = {2, 3, 5, 10};
constexpr std::size_t kAesRounds = 10;
constexpr std::size_t kAesSimd = 1;

struct LifecycleBenchmarkResult {
  double total_ms{0.0};
  AccumulatedRunTimeStatistics run_time_statistics;
  AccumulatedCommunicationStatistics communication_statistics;
};

double ToMilliseconds(std::chrono::steady_clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

std::string CreateLfNormalizedAes128CircuitCopy() {
  const auto source_path = std::string(encrypto::motion::kRootDir) + "/circuits/advanced/aes_128.bristol";
  const auto target_path = std::string(encrypto::motion::kRootDir) + "/build/aes_128_lf_for_tests.bristol";

  std::ifstream source(source_path, std::ios::binary);
  if (!source.is_open()) {
    throw std::runtime_error("Cannot open AES128 Bristol circuit for test");
  }
  std::string content((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());

  std::ofstream target(target_path, std::ios::binary | std::ios::trunc);
  if (!target.is_open()) {
    throw std::runtime_error("Cannot create normalized AES128 Bristol circuit copy for test");
  }
  target.write(content.data(), static_cast<std::streamsize>(content.size()));
  target.close();
  return target_path;
}

const encrypto::motion::AlgorithmDescription& GetAes128Algorithm() {
  static const auto kAesAlgorithm = [] {
    const auto normalized_path = CreateLfNormalizedAes128CircuitCopy();
    return encrypto::motion::AlgorithmDescription::FromBristol(normalized_path);
  }();
  return kAesAlgorithm;
}

void ConfigureParties(std::vector<std::unique_ptr<Party>>& parties) {
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
}

void ResetAllParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Reset(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void FinishAllParties(std::vector<std::unique_ptr<Party>>& parties) {
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (auto& party : parties) {
    futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
  }
  for (auto& future : futures) {
    future.get();
  }
}

void RunAes128RoundAndCollectRunTime(std::vector<std::unique_ptr<Party>>& parties, std::size_t round,
                                     AccumulatedRunTimeStatistics& run_time_statistics) {
  std::vector<encrypto::motion::ShareWrapper> outputs(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    std::vector<BitVector<>> local_input(256, BitVector<>(kAesSimd, false));
    if (party_id == 0) {
      for (std::size_t i = 0; i < local_input.size(); ++i) {
        local_input[i] = BitVector<>(kAesSimd, ((i + round) % 2) == 1);
      }
    }

    encrypto::motion::ShareWrapper input_share(
        parties.at(party_id)->In<kAesProtocol>(std::move(local_input), 0));
    auto aes_output = input_share.Evaluate(GetAes128Algorithm());
    outputs.at(party_id) = aes_output.Out(0);
  }

  std::vector<BitVector<>> opened_output;
  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs, &opened_output] {
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

  ASSERT_EQ(opened_output.size(), 128u);

  for (auto& party : parties) {
    const auto& runs = party->GetBackend()->GetRunTimeStatistics();
    ASSERT_FALSE(runs.empty());
    run_time_statistics.Add(runs.back());
  }
}

LifecycleBenchmarkResult BenchmarkAes128UsingReset(std::size_t number_of_parties) {
  LifecycleBenchmarkResult result;
  const auto total_start = std::chrono::steady_clock::now();

  auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
  ConfigureParties(parties);

  for (std::size_t round = 0; round < kAesRounds; ++round) {
    RunAes128RoundAndCollectRunTime(parties, round, result.run_time_statistics);
    if (round + 1 < kAesRounds) {
      ResetAllParties(parties);
    }
  }

  for (auto& party : parties) {
    result.communication_statistics.Add(
        party->GetBackend()->GetCommunicationLayer().GetTransportStatistics());
  }
  FinishAllParties(parties);

  result.total_ms = ToMilliseconds(std::chrono::steady_clock::now() - total_start);
  return result;
}

LifecycleBenchmarkResult BenchmarkAes128UsingFinish(std::size_t number_of_parties) {
  LifecycleBenchmarkResult result;
  const auto total_start = std::chrono::steady_clock::now();

  for (std::size_t round = 0; round < kAesRounds; ++round) {
    auto parties = encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
    ConfigureParties(parties);

    RunAes128RoundAndCollectRunTime(parties, round, result.run_time_statistics);

    for (auto& party : parties) {
      result.communication_statistics.Add(
          party->GetBackend()->GetCommunicationLayer().GetTransportStatistics());
    }
    FinishAllParties(parties);
  }

  result.total_ms = ToMilliseconds(std::chrono::steady_clock::now() - total_start);
  return result;
}

TEST(Aes128ResetFinish, Aes128ResetVsFinishTotalTime_10Rounds_2_3_5_10Parties) {
  for (const auto number_of_parties : kAesPartyCounts) {
    const auto reset_result = BenchmarkAes128UsingReset(number_of_parties);
    const auto finish_result = BenchmarkAes128UsingFinish(number_of_parties);

    const auto reset_name = "AES128 Reset strategy (" + std::to_string(number_of_parties) +
                            " parties, " + std::to_string(kAesRounds) + " rounds)";
    const auto finish_name = "AES128 Finish strategy (" + std::to_string(number_of_parties) +
                             " parties, " + std::to_string(kAesRounds) + " rounds)";

    std::cout << PrintStatistics(reset_name, reset_result.run_time_statistics,
                                 reset_result.communication_statistics);
    std::cout << PrintStatistics(finish_name, finish_result.run_time_statistics,
                                 finish_result.communication_statistics);

    const auto ratio =
        finish_result.total_ms > 0.0 ? (reset_result.total_ms / finish_result.total_ms) : 0.0;
    std::cout << "AES128 lifecycle total elapsed (ms): parties=" << number_of_parties
              << ", reset_total=" << reset_result.total_ms
              << ", finish_total=" << finish_result.total_ms << ", reset/finish=" << ratio
              << "\n";

    EXPECT_GT(reset_result.total_ms, 0.0);
    EXPECT_GT(finish_result.total_ms, 0.0);
  }
}

}  // namespace