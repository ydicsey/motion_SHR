// MIT License

#include <gtest/gtest.h>

#include <string>

#include "algorithm/algorithm_description.h"
#include "utility/config.h"

namespace {

TEST(AlgorithmDescription, FromAbyPreservesInputOrder) {
  const auto path = std::string(encrypto::motion::kRootDir) + "/circuits/aby/fromaby_input_order_64.aby";
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(path);

  ASSERT_EQ(algorithm.number_of_input_wires_parent_a, 64);
  EXPECT_FALSE(algorithm.number_of_input_wires_parent_b.has_value());
  ASSERT_EQ(algorithm.number_of_gates, 1);
  ASSERT_EQ(algorithm.gates.size(), 1);
  EXPECT_EQ(algorithm.number_of_wires, 67);
  ASSERT_EQ(algorithm.number_of_output_wires, 1);
  ASSERT_EQ(algorithm.output_wire_indices.size(), 1);
  EXPECT_EQ(algorithm.output_wire_indices[0], 66);

  const auto& gate = algorithm.gates[0];
  EXPECT_EQ(gate.type, encrypto::motion::PrimitiveOperationType::kXor);
  EXPECT_EQ(gate.parent_a, 0);
  ASSERT_TRUE(gate.parent_b.has_value());
  EXPECT_EQ(*gate.parent_b, 65);
  EXPECT_EQ(gate.output_wire, 66);

  ASSERT_EQ(algorithm.constant_wires.size(), 67);
  ASSERT_TRUE(algorithm.constant_wires[64].has_value());
  EXPECT_FALSE(*algorithm.constant_wires[64]);
  ASSERT_TRUE(algorithm.constant_wires[65].has_value());
  EXPECT_TRUE(*algorithm.constant_wires[65]);
}

TEST(AlgorithmDescription, FromAbyParsesMuxWithConstantInputs) {
  const auto path = std::string(encrypto::motion::kRootDir) + "/circuits/aby/fromaby_mux_constants.aby";
  const auto algorithm = encrypto::motion::AlgorithmDescription::FromAby(path);

  ASSERT_EQ(algorithm.number_of_input_wires_parent_a, 1);
  EXPECT_FALSE(algorithm.number_of_input_wires_parent_b.has_value());
  ASSERT_EQ(algorithm.number_of_gates, 1);
  ASSERT_EQ(algorithm.gates.size(), 1);
  EXPECT_EQ(algorithm.number_of_wires, 4);
  ASSERT_EQ(algorithm.number_of_output_wires, 1);
  ASSERT_EQ(algorithm.output_wire_indices.size(), 1);
  EXPECT_EQ(algorithm.output_wire_indices[0], 3);

  const auto& gate = algorithm.gates[0];
  EXPECT_EQ(gate.type, encrypto::motion::PrimitiveOperationType::kMux);
  EXPECT_EQ(gate.parent_a, 1);
  ASSERT_TRUE(gate.parent_b.has_value());
  EXPECT_EQ(*gate.parent_b, 2);
  ASSERT_TRUE(gate.selection_bit.has_value());
  EXPECT_EQ(*gate.selection_bit, 0);
  EXPECT_EQ(gate.output_wire, 3);

  ASSERT_EQ(algorithm.constant_wires.size(), 4);
  ASSERT_TRUE(algorithm.constant_wires[1].has_value());
  EXPECT_FALSE(*algorithm.constant_wires[1]);
  ASSERT_TRUE(algorithm.constant_wires[2].has_value());
  EXPECT_TRUE(*algorithm.constant_wires[2]);
}

}  // namespace
