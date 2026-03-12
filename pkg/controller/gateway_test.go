package controller

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestSetGatewayConditions(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 1,
		},
	}

	t.Run("error setting conditions", func(t *testing.T) {
		newGw := gw.DeepCopy()
		setGatewayConditions(newGw, nil, fmt.Errorf("test error"))

		if len(newGw.Status.Conditions) != 2 {
			t.Fatalf("expected 2 conditions, got %d", len(newGw.Status.Conditions))
		}

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected programmed condition to be false")
		}
	})

	t.Run("success all listeners programmed", func(t *testing.T) {
		newGw := gw.DeepCopy()
		listenerStatuses := []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionTrue,
					},
				},
			},
		}
		setGatewayConditions(newGw, listenerStatuses, nil)

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionTrue {
			t.Errorf("expected programmed condition to be true")
		}
	})

	t.Run("success some listeners not programmed", func(t *testing.T) {
		newGw := gw.DeepCopy()
		listenerStatuses := []gatewayv1.ListenerStatus{
			{
				Name: "http",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionTrue,
					},
				},
			},
			{
				Name: "https",
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.ListenerConditionProgrammed),
						Status: metav1.ConditionFalse,
					},
				},
			},
		}
		setGatewayConditions(newGw, listenerStatuses, nil)

		var programmedCondition *metav1.Condition
		for i, c := range newGw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmedCondition = &newGw.Status.Conditions[i]
				break
			}
		}
		if programmedCondition == nil || programmedCondition.Status != metav1.ConditionFalse {
			t.Errorf("expected programmed condition to be false")
		}
	})
}
