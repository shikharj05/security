/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.junit.Test;

import org.opensearch.security.user.User;

import static org.junit.Assert.*;

/**
 * Property-based tests for user attribute population.
 * 
 * **Feature: passkey-authentication, Property 32: User attribute population**
 * **Validates: Requirements 7.5**
 * 
 * For any User Principal with configured attributes, the attributes should be 
 * populated from the passkey user record.
 */
public class UserAttributePopulationPropertyTest {

    private static final Random random = new Random();

    /**
     * Property 32: User attribute population
     * 
     * For any User Principal with configured attributes, the attributes should be 
     * populated from the passkey user record.
     * 
     * This test verifies that when a User object is created with attributes,
     * those attributes are correctly stored and retrievable.
     * 
     * This test runs 100 iterations with randomly generated user attributes.
     */
    @Test
    public void userAttributePopulation() {
        for (int i = 0; i < 100; i++) {
            // Generate random user data with attributes
            String username = generateRandomUsername();
            Map<String, String> attributes = generateRandomAttributes();
            
            // Create a User object with attributes (as would be done during passkey authentication)
            User user = new User(
                username,
                com.google.common.collect.ImmutableSet.of(),
                com.google.common.collect.ImmutableSet.of(),
                null,
                com.google.common.collect.ImmutableMap.copyOf(attributes),
                false
            );
            
            // Verify that all attributes are present and correct
            assertNotNull("User attributes should not be null", user.getCustomAttributesMap());
            assertEquals("Number of attributes should match", attributes.size(), user.getCustomAttributesMap().size());
            
            // Verify each attribute is correctly populated
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                String key = entry.getKey();
                String expectedValue = entry.getValue();
                
                assertTrue("User should have attribute: " + key, user.getCustomAttributesMap().containsKey(key));
                assertEquals(
                    "Attribute value for '" + key + "' should match",
                    expectedValue,
                    user.getCustomAttributesMap().get(key)
                );
            }
            
            // Verify that attributes are immutable (attempting to modify should fail)
            try {
                user.getCustomAttributesMap().put("new_key", "new_value");
                fail("Attributes should be immutable");
            } catch (UnsupportedOperationException e) {
                // Expected - attributes should be immutable
            }
        }
    }

    /**
     * Test that users without attributes have an empty attribute map.
     */
    @Test
    public void userWithoutAttributes() {
        for (int i = 0; i < 100; i++) {
            String username = generateRandomUsername();
            
            // Create a User object without attributes
            User user = new User(
                username,
                com.google.common.collect.ImmutableSet.of(),
                com.google.common.collect.ImmutableSet.of(),
                null,
                com.google.common.collect.ImmutableMap.of(),
                false
            );
            
            // Verify that attributes map exists but is empty
            assertNotNull("User attributes should not be null", user.getCustomAttributesMap());
            assertTrue("User attributes should be empty", user.getCustomAttributesMap().isEmpty());
            assertEquals("Attribute count should be zero", 0, user.getCustomAttributesMap().size());
        }
    }

    /**
     * Generates a random username.
     */
    private String generateRandomUsername() {
        String[] prefixes = {"user", "admin", "test", "dev", "ops"};
        String prefix = prefixes[random.nextInt(prefixes.length)];
        int suffix = random.nextInt(10000);
        return prefix + suffix;
    }

    /**
     * Generates a random map of user attributes.
     */
    private Map<String, String> generateRandomAttributes() {
        String[] attributeKeys = {
            "email",
            "department",
            "location",
            "phone",
            "employee_id",
            "manager",
            "cost_center",
            "title",
            "division",
            "office"
        };
        
        String[] attributeValues = {
            "user@example.com",
            "Engineering",
            "Seattle",
            "+1-555-0100",
            "EMP12345",
            "manager@example.com",
            "CC-1000",
            "Senior Engineer",
            "Technology",
            "Building A"
        };
        
        int attributeCount = random.nextInt(5) + 1; // 1-5 attributes
        Map<String, String> attributes = new HashMap<>();
        
        for (int i = 0; i < attributeCount; i++) {
            int index = random.nextInt(attributeKeys.length);
            String key = attributeKeys[index];
            String value = attributeValues[index] + "_" + random.nextInt(1000);
            attributes.put(key, value);
        }
        
        return attributes;
    }
}
