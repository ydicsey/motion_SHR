// MIT License
//
// Copyright (c) 2026
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <future>
#include <vector>

#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"

namespace {

using namespace encrypto::motion;

std::size_t GetExpectedWorkerThreadCount(std::size_t configured_thread_count) {
  if (configured_thread_count == 0) {
    return 0;
  }
  return std::max<std::size_t>(2, configured_thread_count);
}

void RunSimpleBooleanInputOutputRound(std::vector<PartyPointer>& parties) {
  constexpr auto kBooleanGmw = MpcProtocol::kBooleanGmw;
  std::vector<ShareWrapper> outputs;
  outputs.reserve(parties.size());

  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    const bool input = (party_id == 0u);
    ShareWrapper share_input = parties.at(party_id)->In<kBooleanGmw>(input, 0u);
    outputs.emplace_back(share_input.Out(0u));
  }

  std::vector<std::future<void>> futures;
  futures.reserve(parties.size());
  for (std::size_t party_id = 0; party_id < parties.size(); ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, &parties, &outputs] {
      parties.at(party_id)->Run();
      if (party_id == 0u) {
        EXPECT_TRUE(outputs.at(party_id).As<bool>());
      }
      parties.at(party_id)->Finish();
    }));
  }

  for (auto& future : futures) {
    future.get();
  }
}

TEST(ThreadPoolConfiguration, SetNumOfThreads_0_1_2_AreAppliedAfterPartyConstruction) {
  constexpr std::size_t number_of_parties = 2;
  constexpr std::array<std::size_t, 3> configured_thread_counts = {0, 1, 2};

  for (const auto configured_thread_count : configured_thread_counts) {
    auto parties = MakeLocallyConnectedParties(number_of_parties, kPortOffset);

    for (auto& party : parties) {
      party->GetLogger()->SetEnabled(false);
      party->GetConfiguration()->SetOnlineAfterSetup(false);
      party->GetConfiguration()->SetNumOfThreads(configured_thread_count);

      EXPECT_EQ(party->GetConfiguration()->GetNumOfThreads(), configured_thread_count);
      EXPECT_EQ(party->GetBackend()->GetGateExecutorWorkerThreadCountForTesting(),
                GetExpectedWorkerThreadCount(configured_thread_count));
    }

    RunSimpleBooleanInputOutputRound(parties);
  }
}

}  // namespace
